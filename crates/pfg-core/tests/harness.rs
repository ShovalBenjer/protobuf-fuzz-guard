//! Harness-generation tests, ported from `test_harness_gen.py`, plus the new
//! Rust target and `insta` snapshots of every language's output.

use pfg_core::{generate_all, generate_harness, parse_proto};

#[test]
fn python_harness_contents() {
    let content = r#"
    syntax = "proto3";
    package test;
    message Person {
        string name = 1;
        int32 age = 2;
    }
    "#;
    let proto = parse_proto(content, "person.proto");
    let code = generate_harness(&proto, &proto.messages[0], "python").unwrap();
    assert!(code.contains("def fuzz_person"));
    assert!(code.contains("ParseFromString"));
    assert!(code.contains("test.Person") || code.contains("Person"));
}

#[test]
fn cpp_harness_contents() {
    let content = r"
    message Data {
        bytes payload = 1;
    }
    ";
    let proto = parse_proto(content, "data.proto");
    let code = generate_harness(&proto, &proto.messages[0], "cpp").unwrap();
    assert!(code.contains("LLVMFuzzerTestOneInput"));
    assert!(code.contains("ParseFromArray"));
}

#[test]
fn go_harness_contents() {
    let content = r"
    message Event {
        string name = 1;
    }
    ";
    let proto = parse_proto(content, "event.proto");
    let code = generate_harness(&proto, &proto.messages[0], "go").unwrap();
    assert!(code.contains("Fuzzevent"));
    assert!(code.contains("proto.Unmarshal"));
}

#[test]
fn rust_harness_contents() {
    let content = r#"
    syntax = "proto3";
    package demo;
    message Payload {
        bytes data = 1;
    }
    "#;
    let proto = parse_proto(content, "payload.proto");
    let code = generate_harness(&proto, &proto.messages[0], "rust").unwrap();
    assert!(code.contains("fuzz_target!"));
    assert!(code.contains("use prost::Message;"));
    assert!(code.contains("Payload::decode"));
    assert!(code.contains("RUSTSEC-2020-0002"));
}

#[test]
fn generate_all_default_languages() {
    let content = r"
    message Msg {
        string val = 1;
    }
    ";
    let proto = parse_proto(content, "msg.proto");
    let result = generate_all(&proto, None).unwrap();
    let langs: Vec<_> = result.iter().map(|(l, _)| *l).collect();
    assert!(langs.contains(&"python"));
    assert!(langs.contains(&"cpp"));
    assert!(langs.contains(&"go"));
    assert!(langs.contains(&"rust"));
    let python = result.iter().find(|(l, _)| *l == "python").unwrap();
    assert_eq!(python.1.len(), 1);
}

#[test]
fn generate_specific_language() {
    let content = "message Msg { string val = 1; }";
    let proto = parse_proto(content, "msg.proto");
    let result = generate_all(&proto, Some(&["python"])).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, "python");
}

#[test]
fn unsupported_language_errors() {
    let content = "message M { string v = 1; }";
    let proto = parse_proto(content, "");
    let err = generate_harness(&proto, &proto.messages[0], "java").unwrap_err();
    assert!(err.to_string().contains("java"));
}

// ---- snapshots ---------------------------------------------------------------

fn sample() -> pfg_core::ProtoFile {
    let content = r#"
    syntax = "proto3";
    package acme.v1;
    message Person {
        string name = 1;
        int32 age = 2;
    }
    "#;
    parse_proto(content, "person.proto")
}

#[test]
fn snapshot_python() {
    let proto = sample();
    let code = generate_harness(&proto, &proto.messages[0], "python").unwrap();
    insta::assert_snapshot!("harness_python", code);
}

#[test]
fn snapshot_cpp() {
    let proto = sample();
    let code = generate_harness(&proto, &proto.messages[0], "cpp").unwrap();
    insta::assert_snapshot!("harness_cpp", code);
}

#[test]
fn snapshot_go() {
    let proto = sample();
    let code = generate_harness(&proto, &proto.messages[0], "go").unwrap();
    insta::assert_snapshot!("harness_go", code);
}

#[test]
fn snapshot_rust() {
    let proto = sample();
    let code = generate_harness(&proto, &proto.messages[0], "rust").unwrap();
    insta::assert_snapshot!("harness_rust", code);
}
