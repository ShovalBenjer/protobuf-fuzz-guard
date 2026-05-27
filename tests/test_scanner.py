"""Tests for scanner — CVE pattern detection."""

from protobuf_fuzz_guard.proto_parser import parse_proto
from protobuf_fuzz_guard.scanner import scan


def test_deep_nesting_critical():
    content = """
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
    """
    proto = parse_proto(content, "deep.proto")
    findings = scan(proto)
    criticals = [f for f in findings if f.severity == "critical"]
    assert len(criticals) >= 1
    assert any("nesting depth" in f.message.lower() for f in criticals)


def test_recursive_ref_critical():
    content = """
    message Node {
        Node child = 1;
    }
    """
    proto = parse_proto(content, "recursive.proto")
    findings = scan(proto)
    criticals = [f for f in findings if f.severity == "critical"]
    assert any("recursive" in f.message.lower() for f in criticals)


def test_clean_proto_no_findings():
    content = """
    message Simple {
        string name = 1;
        int32 value = 2;
    }
    """
    proto = parse_proto(content, "clean.proto")
    findings = scan(proto)
    assert len(findings) == 0


def test_repeated_nested_warning():
    content = """
    message Container {
        repeated Item items = 1;
    }
    message Item {
        string name = 1;
    }
    """
    proto = parse_proto(content, "repeated.proto")
    findings = scan(proto)
    warnings = [f for f in findings if f.severity == "warning"]
    assert any("repeated nested" in f.message.lower() for f in warnings)


def test_moderate_depth_warning():
    content = """
    message A {
        message B {
            message C {
                string val = 1;
            }
        }
    }
    """
    proto = parse_proto(content, "moderate.proto")
    findings = scan(proto)
    warnings = [f for f in findings if f.severity == "warning"]
    assert any("moderate" in f.message.lower() for f in warnings)
