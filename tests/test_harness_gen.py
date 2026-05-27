"""Tests for harness generation."""

from protobuf_fuzz_guard.harness_gen import generate_harness, generate_all
from protobuf_fuzz_guard.proto_parser import parse_proto


def test_generate_python_harness():
    content = """
    syntax = "proto3";
    package test;
    message Person {
        string name = 1;
        int32 age = 2;
    }
    """
    proto = parse_proto(content, "person.proto")
    code = generate_harness(proto, proto.messages[0], "python")
    assert "def fuzz_person" in code
    assert "ParseFromString" in code
    assert "test.Person" in code or "Person" in code


def test_generate_cpp_harness():
    content = """
    message Data {
        bytes payload = 1;
    }
    """
    proto = parse_proto(content, "data.proto")
    code = generate_harness(proto, proto.messages[0], "cpp")
    assert "LLVMFuzzerTestOneInput" in code
    assert "ParseFromArray" in code


def test_generate_go_harness():
    content = """
    message Event {
        string name = 1;
    }
    """
    proto = parse_proto(content, "event.proto")
    code = generate_harness(proto, proto.messages[0], "go")
    assert "Fuzzevent" in code
    assert "proto.Unmarshal" in code


def test_generate_all_languages():
    content = """
    message Msg {
        string val = 1;
    }
    """
    proto = parse_proto(content, "msg.proto")
    result = generate_all(proto)
    assert "python" in result
    assert "cpp" in result
    assert "go" in result
    assert len(result["python"]) == 1


def test_generate_specific_language():
    content = """
    message Msg {
        string val = 1;
    }
    """
    proto = parse_proto(content, "msg.proto")
    result = generate_all(proto, languages=["python"])
    assert "python" in result
    assert "cpp" not in result


def test_unsupported_language_raises():
    content = "message M { string v = 1; }"
    proto = parse_proto(content)
    try:
        generate_harness(proto, proto.messages[0], "rust")
        assert False, "Should have raised"
    except ValueError as e:
        assert "rust" in str(e)
