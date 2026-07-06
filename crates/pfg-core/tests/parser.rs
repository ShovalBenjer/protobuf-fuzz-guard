//! Parser tests, ported from the reference `test_proto_parser.py`, plus span checks.

use pfg_core::{has_recursive_refs, max_nesting_depth, parse_proto};

#[test]
fn parse_simple_message() {
    let content = r#"
    syntax = "proto3";
    package example;

    message Person {
        string name = 1;
        int32 age = 2;
    }
    "#;
    let proto = parse_proto(content, "example.proto");
    assert_eq!(proto.syntax, "proto3");
    assert_eq!(proto.package, "example");
    assert_eq!(proto.messages.len(), 1);
    assert_eq!(proto.messages[0].name, "Person");
    assert_eq!(proto.messages[0].fields.len(), 2);
    assert_eq!(proto.messages[0].fields[0].name, "name");
    assert_eq!(proto.messages[0].fields[0].ty, "string");
    assert_eq!(proto.messages[0].fields[0].number, 1);
}

#[test]
fn parse_nested_messages() {
    let content = r"
    message Outer {
        message Inner {
            string value = 1;
        }
        Inner inner = 1;
    }
    ";
    let proto = parse_proto(content, "");
    assert_eq!(proto.messages.len(), 1);
    assert_eq!(proto.messages[0].name, "Outer");
    assert_eq!(proto.messages[0].nested.len(), 1);
    assert_eq!(proto.messages[0].nested[0].name, "Inner");
    // Correct stack popping: `inner` belongs to Outer, not the closed Inner.
    assert!(proto.messages[0].fields.iter().any(|f| f.name == "inner"));
}

#[test]
fn nesting_depth_metric() {
    let content = r"
    message A {
        message B {
            message C {
                string val = 1;
            }
        }
    }
    ";
    let proto = parse_proto(content, "");
    assert_eq!(max_nesting_depth(&proto), 3);
}

#[test]
fn recursive_refs_in_order() {
    let content = r"
    message TreeNode {
        string value = 1;
        TreeNode left = 2;
        TreeNode right = 3;
    }
    ";
    let proto = parse_proto(content, "");
    let recursions = has_recursive_refs(&proto);
    assert_eq!(recursions.len(), 2);
    assert_eq!(recursions[0], ("TreeNode".into(), "left".into()));
    assert_eq!(recursions[1], ("TreeNode".into(), "right".into()));
}

#[test]
fn repeated_and_optional_labels() {
    let content = r"
    message Msg {
        repeated string items = 1;
        optional string label = 2;
    }
    ";
    let proto = parse_proto(content, "");
    let fields = &proto.messages[0].fields;
    assert!(fields[0].repeated);
    assert!(!fields[0].optional);
    assert!(fields[1].optional);
    assert!(!fields[1].repeated);
}

#[test]
fn parse_imports() {
    let content = r#"
    syntax = "proto3";
    import "google/protobuf/timestamp.proto";
    import "common/types.proto";

    message Event {
        string name = 1;
    }
    "#;
    let proto = parse_proto(content, "");
    assert_eq!(proto.imports.len(), 2);
    assert!(proto
        .imports
        .contains(&"google/protobuf/timestamp.proto".to_string()));
}

#[test]
fn field_span_points_at_declaration() {
    let content = "message M {\n    string name = 1;\n}\n";
    let proto = parse_proto(content, "m.proto");
    let field = &proto.messages[0].fields[0];
    let slice = &content[field.span.start..field.span.end];
    assert_eq!(slice, "string name = 1;");
}

#[test]
fn map_field_type_is_captured() {
    let content = "message M {\n    map<string, int32> counts = 1;\n}\n";
    let proto = parse_proto(content, "");
    assert_eq!(proto.messages[0].fields[0].ty, "map<string, int32>");
    assert_eq!(proto.messages[0].fields[0].name, "counts");
}
