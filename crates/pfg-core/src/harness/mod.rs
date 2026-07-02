//! Generate fuzz harnesses for protobuf messages across languages.
//!
//! Ports the reference Python/C++/Go templates and adds a first-class **Rust**
//! target: a structure-aware `libfuzzer-sys` harness that decodes with `prost`
//! and round-trips, inheriting prost's built-in recursion limit as a DoS guard
//! (research §6, §9).

use std::path::Path;

use crate::proto::{ProtoFile, ProtoMessage};

mod templates;

/// Languages for which a harness can be generated.
pub const LANGUAGES: &[&str] = &["python", "cpp", "go", "rust"];

/// Error returned when a harness cannot be generated.
#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error("No template for language: {0}")]
    UnsupportedLanguage(String),
}

/// File extension used for a generated harness in `language`.
#[must_use]
pub fn file_extension(language: &str) -> Option<&'static str> {
    match language {
        "python" => Some(".py"),
        "cpp" => Some(".cc"),
        "go" => Some("_test.go"),
        "rust" => Some(".rs"),
        _ => None,
    }
}

fn safe_name(name: &str) -> String {
    name.replace('.', "_").to_lowercase()
}

fn go_package(proto: &ProtoFile) -> String {
    if proto.package.is_empty() {
        "fuzz".to_string()
    } else {
        proto.package.replace('.', "_")
    }
}

fn proto_module_py(proto: &ProtoFile) -> String {
    if proto.package.is_empty() {
        format!("{}_pb2", file_stem(proto))
    } else {
        format!("{}_pb2", proto.package.replace('.', "_"))
    }
}

fn proto_module_rust(proto: &ProtoFile) -> String {
    if proto.package.is_empty() {
        file_stem(proto)
    } else {
        proto.package.replace('.', "_")
    }
}

fn file_stem(proto: &ProtoFile) -> String {
    if proto.file_path.is_empty() {
        "proto".to_string()
    } else {
        Path::new(&proto.file_path)
            .file_stem()
            .map_or_else(|| "proto".to_string(), |s| s.to_string_lossy().into_owned())
    }
}

fn package_prefix(proto: &ProtoFile) -> String {
    if proto.package.is_empty() {
        String::new()
    } else {
        format!("{}.", proto.package)
    }
}

/// Generate a harness for `message` in `language`.
pub fn generate_harness(
    proto: &ProtoFile,
    message: &ProtoMessage,
    language: &str,
) -> Result<String, HarnessError> {
    let template = match language {
        "python" => templates::PYTHON,
        "cpp" => templates::CPP,
        "go" => templates::GO,
        "rust" => templates::RUST,
        other => return Err(HarnessError::UnsupportedLanguage(other.to_string())),
    };

    let safe = safe_name(&message.name);
    let pkg = package_prefix(proto);

    let rendered = template
        .replace("%MESSAGE_NAME%", &message.name)
        .replace("%SAFE_NAME%", &safe)
        .replace("%PROTO_PACKAGE%", &pkg)
        .replace("%PROTO_MODULE%", &proto_module_py(proto))
        .replace("%PROTO_MODULE_RUST%", &proto_module_rust(proto))
        .replace("%PROTO_BASENAME%", &file_stem(proto))
        .replace("%PROTO_IMPORT%", "\"google.golang.org/protobuf/proto\"")
        .replace("%GO_PACKAGE%", &go_package(proto));

    Ok(rendered)
}

/// A language's generated harnesses: `(message_name, code)` per message.
pub type LangHarnesses = (&'static str, Vec<(String, String)>);

/// Generate harnesses for every message in the given languages (default: all).
///
/// # Errors
/// Returns [`HarnessError::UnsupportedLanguage`] if any requested language has
/// no template.
pub fn generate_all(
    proto: &ProtoFile,
    languages: Option<&[&str]>,
) -> Result<Vec<LangHarnesses>, HarnessError> {
    let langs = languages.unwrap_or(LANGUAGES);
    let mut result = Vec::new();
    for &lang in langs {
        let canonical = *LANGUAGES
            .iter()
            .find(|&&l| l == lang)
            .ok_or_else(|| HarnessError::UnsupportedLanguage(lang.to_string()))?;
        let mut harnesses = Vec::new();
        for msg in &proto.messages {
            let code = generate_harness(proto, msg, canonical)?;
            harnesses.push((msg.name.clone(), code));
        }
        result.push((canonical, harnesses));
    }
    Ok(result)
}
