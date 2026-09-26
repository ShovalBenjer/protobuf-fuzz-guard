//! Schema-check for local (SLM) model outputs.
//!
//! ADR-0009: SLM outputs are untrusted until schema-checked. A local model
//! emits invalid structured output far more often than a frontier model, so
//! every local output is validated by **deterministic code** before use:
//! length-capped, must be one JSON object, required fields present.
//! Anything else is rejected — never repaired, never passed through.
//!
//! Std-only: the JSON shape check is hand-rolled (balanced delimiters,
//! string-aware) so this crate keeps zero dependencies.

/// Output-length cap for local model responses (OWASP LLM01:2025: cap output
/// length to close exfiltration bandwidth; here it bounds the validator too).
pub const MAX_LOCAL_OUTPUT_LEN: usize = 8000;

/// Why a local model output was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// Output exceeded the length cap.
    TooLong { len: usize, max: usize },
    /// Not a single JSON object (unbalanced delimiters, wrong top level,
    /// or trailing data after the object).
    NotJsonObject,
    /// A required top-level field is absent.
    MissingField(String),
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaError::TooLong { len, max } => {
                write!(f, "local output too long: {len} chars > cap {max}")
            }
            SchemaError::NotJsonObject => write!(f, "local output is not a single JSON object"),
            SchemaError::MissingField(field) => {
                write!(f, "local output missing required field \"{field}\"")
            }
        }
    }
}

/// Validate a local model's structured output deterministically.
///
/// `required` lists top-level field names the output must contain.
/// Returns `Ok(())` only when all checks pass; the output is never mutated.
pub fn validate_local_output(output: &str, required: &[&str]) -> Result<(), SchemaError> {
    let len = output.chars().count();
    if len > MAX_LOCAL_OUTPUT_LEN {
        return Err(SchemaError::TooLong {
            len,
            max: MAX_LOCAL_OUTPUT_LEN,
        });
    }
    let keys = top_level_keys(output).ok_or(SchemaError::NotJsonObject)?;
    for field in required {
        if !keys.iter().any(|k| k == field) {
            return Err(SchemaError::MissingField((*field).to_string()));
        }
    }
    Ok(())
}

/// Extract top-level keys of a single JSON object, or `None` when `s` is not
/// exactly one balanced JSON object (string-aware scan; values are skipped).
fn top_level_keys(s: &str) -> Option<Vec<String>> {
    let t = s.trim();
    let bytes = t.as_bytes();
    if bytes.first() != Some(&b'{') {
        return None;
    }
    let mut keys = Vec::new();
    let mut depth = 0usize;
    let mut idx = 0usize;
    while idx < bytes.len() {
        match bytes[idx] {
            b'"' => {
                // Scan the string; at depth 1 a string followed by ':' is a key.
                let start = idx + 1;
                let mut end = start;
                let mut esc = false;
                while end < bytes.len() {
                    let ch = bytes[end];
                    if esc {
                        esc = false;
                    } else if ch == b'\\' {
                        esc = true;
                    } else if ch == b'"' {
                        break;
                    }
                    end += 1;
                }
                if end >= bytes.len() {
                    return None; // unterminated string
                }
                let mut after = end + 1;
                while after < bytes.len() && bytes[after].is_ascii_whitespace() {
                    after += 1;
                }
                if depth == 1 && after < bytes.len() && bytes[after] == b':' {
                    keys.push(t.get(start..end)?.to_string());
                }
                idx = end + 1; // continue past the closing quote
            }
            b'{' | b'[' => {
                depth += 1;
                idx += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    // The object must end here: only whitespace may follow.
                    return if t.get(idx + 1..).is_some_and(|rest| rest.trim().is_empty()) {
                        Some(keys)
                    } else {
                        None
                    };
                }
                idx += 1;
            }
            _ => idx += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_object_with_required_fields() {
        let out = r#"{"route": "ollama-local", "confidence": 0.9, "nested": {"a": 1}}"#;
        assert!(validate_local_output(out, &["route", "confidence"]).is_ok());
    }

    #[test]
    fn rejects_missing_field() {
        let out = r#"{"route": "ollama-local"}"#;
        assert_eq!(
            validate_local_output(out, &["route", "confidence"]),
            Err(SchemaError::MissingField("confidence".to_string()))
        );
    }

    #[test]
    fn rejects_non_object_and_trailing_data() {
        assert_eq!(
            validate_local_output("[1, 2]", &[]),
            Err(SchemaError::NotJsonObject)
        );
        assert_eq!(
            validate_local_output(r#"{"a": 1} {"b": 2}"#, &[]),
            Err(SchemaError::NotJsonObject)
        );
        assert_eq!(
            validate_local_output(r#"{"a": 1"#, &[]),
            Err(SchemaError::NotJsonObject)
        );
    }

    #[test]
    fn rejects_overlong_output() {
        let out = "x".repeat(MAX_LOCAL_OUTPUT_LEN + 1);
        assert!(matches!(
            validate_local_output(&out, &[]),
            Err(SchemaError::TooLong { .. })
        ));
    }

    #[test]
    fn ignores_braces_inside_strings() {
        let out = r#"{"msg": "a } { b", "route": "x"}"#;
        assert!(validate_local_output(out, &["msg", "route"]).is_ok());
    }

    #[test]
    fn nested_keys_are_not_top_level() {
        let out = r#"{"outer": {"route": "x"}}"#;
        assert_eq!(
            validate_local_output(out, &["route"]),
            Err(SchemaError::MissingField("route".to_string()))
        );
    }
}
