//! Harness source templates. Placeholders use `%TOKEN%` markers so the many
//! literal `{`/`}` in the target-language code need no escaping.

pub const PYTHON: &str = r#""""Auto-generated fuzz harness by protobuf-fuzz-guard."""

import sys
from pathlib import Path

# Generated for: %PROTO_PACKAGE%%MESSAGE_NAME%
# Replace %PROTO_MODULE% with your actual compiled protobuf module

def fuzz_%SAFE_NAME%(data: bytes) -> None:
    """Fuzz target: parse raw bytes as %MESSAGE_NAME%."""
    from %PROTO_MODULE% import %MESSAGE_NAME%
    try:
        msg = %MESSAGE_NAME%()
        msg.ParseFromString(data)
        # Access all fields to trigger lazy parsing
        msg.SerializeToString()
        str(msg)
    except Exception:
        pass  # Expected on malformed input


def main():
    """Read from stdin or file argument for manual testing."""
    if len(sys.argv) > 1:
        data = Path(sys.argv[1]).read_bytes()
    else:
        data = sys.stdin.buffer.read()
    fuzz_%SAFE_NAME%(data)


if __name__ == "__main__":
    main()
"#;

pub const CPP: &str = r#"// Auto-generated fuzz harness by protobuf-fuzz-guard.
// Compile: clang++ -fsanitize=fuzzer -lprotobuf %SAFE_NAME%_fuzz.cc

#include <cstdint>
#include <cstring>
#include "%PROTO_BASENAME%.pb.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    %PROTO_PACKAGE%%MESSAGE_NAME% msg;
    // Set recursion limit to catch stack overflows
    msg.set_recursion_depth_limit(64);
    msg.ParseFromArray(data, static_cast<int>(size));
    // Force full parsing by serializing back
    std::string output;
    msg.SerializeToString(&output);
    return 0;
}
"#;

pub const GO: &str = r#"// Auto-generated fuzz harness by protobuf-fuzz-guard.
// Go 1.18+ native fuzz target

package %GO_PACKAGE%

import (
    "testing"
    %PROTO_IMPORT%
)

func Fuzz%SAFE_NAME%(f *testing.F) {
    f.Add([]byte{})  // Seed corpus: empty message
    f.Add([]byte{0x0a, 0x00})  // Seed: field 1, length 0

    f.Fuzz(func(t *testing.T, data []byte) {
        msg := &%PROTO_PACKAGE%%MESSAGE_NAME%{}
        if err := proto.Unmarshal(data, msg); err != nil {
            return
        }
        // Force full parsing
        proto.Marshal(msg)
    })
}
"#;

pub const RUST: &str = r#"// Auto-generated fuzz harness by protobuf-fuzz-guard.
// Structure-aware libFuzzer target for `%MESSAGE_NAME%` using prost.
//
// Run with a nightly toolchain:
//   cargo +nightly fuzz run fuzz_%SAFE_NAME%
//
// prost enforces a recursion/nesting limit of 100 by default (DecodeContext),
// guarding against stack-overflow DoS. See RUSTSEC-2020-0002 and pin prost >= 0.6.1.
#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;

// Replace `%PROTO_MODULE_RUST%` with the module of your generated prost types
// for %PROTO_PACKAGE%%MESSAGE_NAME%.
use %PROTO_MODULE_RUST%::%MESSAGE_NAME%;

fuzz_target!(|data: &[u8]| {
    // Decode untrusted bytes. Errors (including RecursionLimitReached) are expected.
    if let Ok(msg) = %MESSAGE_NAME%::decode(data) {
        // Round-trip: re-encode, then decode again to exercise both directions.
        let mut buf = Vec::with_capacity(msg.encoded_len());
        msg.encode(&mut buf)
            .expect("re-encoding a successfully decoded message is infallible");
        let _ = %MESSAGE_NAME%::decode(buf.as_slice());
    }
});
"#;
