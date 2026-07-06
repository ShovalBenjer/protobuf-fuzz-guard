//! Small hand-written matchers over a single source line.
//!
//! We deliberately avoid a regex dependency: for a security tool, every
//! statically-linked crate is attack surface (research §8), and the
//! CVE-relevant tokens (`message`, `group`, `repeated`, field declarations) are
//! lexically simple. Each matcher returns byte offsets *relative to the line* so
//! the parser can turn them into absolute [`Span`](super::model::Span)s.

fn is_ident_start(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphabetic()
}

fn is_ident_cont(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

fn is_type_char(b: u8) -> bool {
    is_ident_cont(b) || b == b'.'
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
        i += 1;
    }
    i
}

/// `syntax = "..."` → the syntax string.
pub fn match_syntax(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("syntax")?;
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// `package a.b.c;` → the package path.
pub fn match_package(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("package")?;
    if !rest.starts_with([' ', '\t']) {
        return None;
    }
    let rest = rest.trim_start();
    let end = rest.find(';')?;
    let pkg = rest[..end].trim();
    if pkg.is_empty() {
        None
    } else {
        Some(pkg)
    }
}

/// `import "path";` → the import path.
pub fn match_import(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("import")?;
    if !rest.starts_with([' ', '\t']) {
        return None;
    }
    let rest = rest.trim_start().strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// A matched message header, with the name span relative to the line.
pub struct MessageMatch {
    pub name_start: usize,
    pub name_end: usize,
}

/// `message Name {` → the name and its byte range within the line.
pub fn match_message(line: &str) -> Option<MessageMatch> {
    let b = line.as_bytes();
    let mut i = skip_ws(b, 0);
    let kw = "message";
    if !line[i..].starts_with(kw) {
        return None;
    }
    i += kw.len();
    let ws = skip_ws(b, i);
    if ws == i {
        return None; // require whitespace after `message`
    }
    i = ws;
    let name_start = i;
    if i >= b.len() || !is_ident_start(b[i]) {
        return None;
    }
    while i < b.len() && is_ident_cont(b[i]) {
        i += 1;
    }
    let name_end = i;
    i = skip_ws(b, i);
    if i >= b.len() || b[i] != b'{' {
        return None;
    }
    Some(MessageMatch {
        name_start,
        name_end,
    })
}

/// A matched field declaration, with byte ranges relative to the line.
pub struct FieldMatch<'a> {
    pub label: Option<&'a str>,
    pub ty: &'a str,
    pub name: &'a str,
    pub number: i64,
    /// Range covering the whole declaration, first token through `;`.
    pub start: usize,
    pub end: usize,
}

/// `[label] Type name = N;` → the parsed field.
///
/// Mirrors the reference grammar
/// `^\s*(optional|required|repeated)?\s*(map<...>|[\w.]+)\s+(\w+)\s*=\s*(\d+)\s*;`.
#[allow(clippy::too_many_lines)]
pub fn match_field(line: &str) -> Option<FieldMatch<'_>> {
    let b = line.as_bytes();
    let mut i = skip_ws(b, 0);
    let field_start = i;

    // First identifier: may be a label or the start of the type.
    let id0_start = i;
    if i >= b.len() || !is_ident_start(b[i]) {
        return None;
    }
    while i < b.len() && is_ident_cont(b[i]) {
        i += 1;
    }
    let id0 = &line[id0_start..i];

    let (label, type_start) = if matches!(id0, "optional" | "required" | "repeated") {
        let ws = skip_ws(b, i);
        if ws == i {
            return None; // need whitespace between label and type
        }
        (Some(id0), ws)
    } else {
        (None, id0_start)
    };

    // Type: either `map<...>` or a dotted identifier.
    i = type_start;
    let ty_start = i;
    if line[i..].starts_with("map<") {
        i += 4;
        while i < b.len() && b[i] != b'>' {
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        i += 1; // consume '>'
    } else {
        if i >= b.len() || !is_ident_start(b[i]) {
            return None;
        }
        while i < b.len() && is_type_char(b[i]) {
            i += 1;
        }
    }
    let ty = &line[ty_start..i];

    let ws = skip_ws(b, i);
    if ws == i {
        return None; // need whitespace between type and name
    }
    i = ws;

    // Field name.
    let name_start = i;
    if i >= b.len() || !is_ident_start(b[i]) {
        return None;
    }
    while i < b.len() && is_ident_cont(b[i]) {
        i += 1;
    }
    let name = &line[name_start..i];

    i = skip_ws(b, i);
    if i >= b.len() || b[i] != b'=' {
        return None;
    }
    i += 1;
    i = skip_ws(b, i);

    let num_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == num_start {
        return None;
    }
    let number: i64 = line[num_start..i].parse().ok()?;

    i = skip_ws(b, i);
    if i >= b.len() || b[i] != b';' {
        return None;
    }
    let end = i + 1;

    Some(FieldMatch {
        label,
        ty,
        name,
        number,
        start: field_start,
        end,
    })
}
