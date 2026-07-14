"""Generate fuzz harnesses for protobuf messages across languages."""

from pathlib import Path

from .proto_parser import ProtoFile, ProtoMessage

_TEMPLATES = {
    "python": '''"""Auto-generated fuzz harness by protobuf-fuzz-guard."""

import sys
from pathlib import Path

# Generated for: {proto_package}{message_name}
# Replace {proto_module} with your actual compiled protobuf module

def fuzz_{safe_name}(data: bytes) -> None:
    """Fuzz target: parse raw bytes as {message_name}."""
    from {proto_module} import {message_name}
    try:
        msg = {message_name}()
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
    fuzz_{safe_name}(data)


if __name__ == "__main__":
    main()
''',
    "cpp": '''// Auto-generated fuzz harness by protobuf-fuzz-guard.
// Compile: clang++ -fsanitize=fuzzer -lprotobuf {safe_name}_fuzz.cc

#include <cstdint>
#include <cstring>
#include "{proto_basename}.pb.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {{
    {proto_package}{message_name} msg;
    // Set recursion limit to catch stack overflows
    msg.set_recursion_depth_limit(64);
    msg.ParseFromArray(data, static_cast<int>(size));
    // Force full parsing by serializing back
    std::string output;
    msg.SerializeToString(&output);
    return 0;
}}
''',
    "go": '''// Auto-generated fuzz harness by protobuf-fuzz-guard.
// Go 1.18+ native fuzz target

package {go_package}

import (
    "testing"
    {proto_import}
)

func Fuzz{safe_name}(f *testing.F) {{
    f.Add([]byte{{}})  // Seed corpus: empty message
    f.Add([]byte{{0x0a, 0x00}})  // Seed: field 1, length 0

    f.Fuzz(func(t *testing.T, data []byte) {{
        msg := &{proto_package}{message_name}{{}}
        if err := proto.Unmarshal(data, msg); err != nil {{
            return
        }}
        // Force full parsing
        proto.Marshal(msg)
    }})
}}
''',
}


def _safe_name(name: str) -> str:
    return name.replace(".", "_").lower()


def _go_package(proto: ProtoFile) -> str:
    return proto.package.replace(".", "_") if proto.package else "fuzz"


def _proto_module(proto: ProtoFile) -> str:
    if proto.package:
        return proto.package.replace(".", "_") + "_pb2"
    return Path(proto.file_path).stem + "_pb2"


def generate_harness(
    proto: ProtoFile,
    message: ProtoMessage,
    language: str,
) -> str:
    """Generate a fuzz harness for the given message in the target language."""
    template = _TEMPLATES.get(language)
    if not template:
        raise ValueError(f"No template for language: {language}")

    safe = _safe_name(message.name)
    proto_basename = Path(proto.file_path).stem if proto.file_path else "proto"
    pkg = proto.package + "." if proto.package else ""

    return template.format(
        message_name=message.name,
        safe_name=safe,
        proto_package=pkg,
        proto_module=_proto_module(proto),
        proto_basename=proto_basename,
        proto_import=f'"google.golang.org/protobuf/proto"',
        go_package=_go_package(proto),
    )


def generate_all(proto: ProtoFile, languages: list[str] | None = None) -> dict[str, list[tuple[str, str]]]:
    """Generate harnesses for all messages in all target languages.

    Returns: {language: [(message_name, harness_code), ...]}
    """
    if languages is None:
        languages = list(_TEMPLATES.keys())

    result: dict[str, list[tuple[str, str]]] = {}
    for lang in languages:
        harnesses = []
        for msg in proto.messages:
            code = generate_harness(proto, msg, lang)
            harnesses.append((msg.name, code))
        result[lang] = harnesses
    return result
