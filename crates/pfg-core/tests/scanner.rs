//! Scanner tests, ported from the reference `test_scanner.py`.

use pfg_core::{has_critical, parse_proto, scan, Severity};

#[test]
fn deep_nesting_is_critical() {
    let content = r"
    message A {
        message B {
            message C {
                message D {
                    message E {
                        message F {
                            string val = 1;
                        }
                    }
                }
            }
        }
    }
    ";
    let proto = parse_proto(content, "deep.proto");
    let findings = scan(&proto);
    let criticals: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .collect();
    assert!(!criticals.is_empty());
    assert!(criticals
        .iter()
        .any(|f| f.message.to_lowercase().contains("nesting depth")));
    assert!(has_critical(&findings));
}

#[test]
fn recursive_ref_is_critical() {
    let content = r"
    message Node {
        Node child = 1;
    }
    ";
    let proto = parse_proto(content, "recursive.proto");
    let findings = scan(&proto);
    assert!(findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .any(|f| f.message.to_lowercase().contains("recursive")));
}

#[test]
fn clean_proto_has_no_findings() {
    let content = r"
    message Simple {
        string name = 1;
        int32 value = 2;
    }
    ";
    let proto = parse_proto(content, "clean.proto");
    assert!(scan(&proto).is_empty());
}

#[test]
fn repeated_nested_message_is_warning() {
    let content = r"
    message Container {
        repeated Item items = 1;
    }
    message Item {
        string name = 1;
    }
    ";
    let proto = parse_proto(content, "repeated.proto");
    let findings = scan(&proto);
    assert!(findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .any(|f| f.message.to_lowercase().contains("repeated nested")));
}

#[test]
fn moderate_depth_is_warning() {
    let content = r"
    message A {
        message B {
            message C {
                string val = 1;
            }
        }
    }
    ";
    let proto = parse_proto(content, "moderate.proto");
    let findings = scan(&proto);
    assert!(findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .any(|f| f.message.to_lowercase().contains("moderate")));
}

#[test]
fn group_field_flags_cve_2024_7254() {
    let content = "message M {\n    group Legacy = 1;\n}\n";
    let proto = parse_proto(content, "g.proto");
    let findings = scan(&proto);
    // A group-typed field is flagged as the CVE-2024-7254 class.
    // (`group Legacy = 1;` parses with ty == "group".)
    assert!(findings
        .iter()
        .any(|f| f.pattern_id == Some("CVE-2024-7254-CLASS")));
}

#[test]
fn findings_carry_spans() {
    let content = "message Node {\n    Node child = 1;\n}\n";
    let proto = parse_proto(content, "n.proto");
    let findings = scan(&proto);
    let rec = findings
        .iter()
        .find(|f| f.message.contains("Recursive"))
        .expect("recursive finding present");
    let span = rec.span.expect("recursive finding has a span");
    assert_eq!(&content[span.start..span.end], "Node child = 1;");
}
