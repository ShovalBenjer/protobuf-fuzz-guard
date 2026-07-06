//! CLI integration tests, ported from the reference `test_cli.py`.

use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

fn protofuzz() -> Command {
    Command::cargo_bin("protofuzz").unwrap()
}

#[test]
fn patterns_command_lists_cve() {
    protofuzz()
        .arg("patterns")
        .assert()
        .success()
        .stdout(predicate::str::contains("CVE-2024-7254"))
        .stdout(predicate::str::contains("TYPE_GROUP"))
        // New Rust-native advisories surfaced by the research pass.
        .stdout(predicate::str::contains("RUSTSEC-2024-0437"));
}

#[test]
fn scan_clean_proto_succeeds() {
    let dir = tempdir();
    let proto = dir.join("clean.proto");
    fs::write(&proto, "message Simple { string name = 1; }").unwrap();
    protofuzz()
        .args(["scan", proto.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("No findings"));
}

#[test]
fn scan_risky_proto_exits_1() {
    let dir = tempdir();
    let proto = dir.join("risky.proto");
    fs::write(&proto, "message Node {\n    Node child = 1;\n}\n").unwrap();
    protofuzz()
        .args(["scan", proto.to_str().unwrap()])
        .assert()
        .code(1);
}

#[test]
fn scan_json_output_is_array() {
    let dir = tempdir();
    let proto = dir.join("msg.proto");
    fs::write(&proto, "message Msg { string v = 1; }").unwrap();
    let out = protofuzz()
        .args(["scan", proto.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(parsed.is_array());
}

#[test]
fn generate_command_writes_files() {
    let dir = tempdir();
    let proto = dir.join("msg.proto");
    fs::write(
        &proto,
        "syntax = \"proto3\";\nmessage Person { string name = 1; }\n",
    )
    .unwrap();
    let out = dir.join("output");
    protofuzz()
        .args([
            "generate",
            proto.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-l",
            "python",
            "-l",
            "rust",
        ])
        .assert()
        .success();
    assert!(out.join("python").join("fuzz_person.py").exists());
    assert!(out.join("rust").join("fuzz_person.rs").exists());
}

/// Minimal unique temp dir without pulling in an extra crate.
fn tempdir() -> std::path::PathBuf {
    let base = std::env::temp_dir();
    let unique = format!(
        "protofuzz-test-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let dir = base.join(unique);
    fs::create_dir_all(&dir).unwrap();
    dir
}

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
