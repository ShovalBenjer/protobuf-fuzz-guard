"""Tests for proto parser."""

from protobuf_fuzz_guard.proto_parser import parse_proto, max_nesting_depth, has_recursive_refs


def test_parse_simple_message():
    content = """
    syntax = "proto3";
    package example;

    message Person {
        string name = 1;
        int32 age = 2;
    }
    """
    proto = parse_proto(content, "example.proto")
    assert proto.syntax == "proto3"
    assert proto.package == "example"
    assert len(proto.messages) == 1
    assert proto.messages[0].name == "Person"
    assert len(proto.messages[0].fields) == 2
    assert proto.messages[0].fields[0].name == "name"
    assert proto.messages[0].fields[0].type == "string"
    assert proto.messages[0].fields[0].number == 1


def test_parse_nested_messages():
    content = """
    message Outer {
        message Inner {
            string value = 1;
        }
        Inner inner = 1;
    }
    """
    proto = parse_proto(content)
    assert len(proto.messages) == 1
    assert proto.messages[0].name == "Outer"
    assert len(proto.messages[0].nested_messages) == 1
    assert proto.messages[0].nested_messages[0].name == "Inner"


def test_max_nesting_depth():
    content = """
    message A {
        message B {
            message C {
                string val = 1;
            }
        }
    }
    """
    proto = parse_proto(content)
    assert max_nesting_depth(proto) == 3


def test_has_recursive_refs():
    content = """
    message TreeNode {
        string value = 1;
        TreeNode left = 2;
        TreeNode right = 3;
    }
    """
    proto = parse_proto(content)
    recursions = has_recursive_refs(proto)
    assert len(recursions) == 2
    assert recursions[0] == ("TreeNode", "left")
    assert recursions[1] == ("TreeNode", "right")


def test_parse_repeated_fields():
    content = """
    message Msg {
        repeated string items = 1;
        optional string label = 2;
    }
    """
    proto = parse_proto(content)
    fields = proto.messages[0].fields
    assert fields[0].repeated is True
    assert fields[0].optional is False
    assert fields[1].optional is True
    assert fields[1].repeated is False


def test_parse_imports():
    content = '''
    syntax = "proto3";
    import "google/protobuf/timestamp.proto";
    import "common/types.proto";

    message Event {
        string name = 1;
    }
    '''
    proto = parse_proto(content)
    assert len(proto.imports) == 2
    assert "google/protobuf/timestamp.proto" in proto.imports
