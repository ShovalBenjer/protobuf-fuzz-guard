"""Known CVE patterns in protobuf deserialization surfaces."""

from dataclasses import dataclass


@dataclass(frozen=True)
class CVEPattern:
    id: str
    title: str
    description: str
    affected_languages: list[str]
    trigger_pattern: str
    detection_regex: str


PATTERNS: list[CVEPattern] = [
    CVEPattern(
        id="CVE-2024-7254-CLASS",
        title="Unbounded recursion via deeply nested TYPE_GROUP",
        description="UntypedMessage::Decode() did not track recursion depth for TYPE_GROUP fields, "
                    "allowing stack overflow via crafted .proto definitions with deeply nested groups.",
        affected_languages=["cpp"],
        trigger_pattern="group { group { group { ... } } }",
        detection_regex=r"group\s*\{",
    ),
    CVEPattern(
        id="PROTOBUF-UAF-PYTHON-BUFFER",
        title="Use-after-free via Python Buffer Objects in MergeFromString",
        description="MergeFromString accepted buffer objects whose underlying memory could be freed "
                    "while protobuf still held a reference, causing UAF.",
        affected_languages=["python"],
        trigger_pattern="MergeFromString(memoryview(obj))",
        detection_regex=r"MergeFromString\s*\(",
    ),
    CVEPattern(
        id="PROTOBUF-RECURSION-PROTO2",
        title="Unbounded stack recursion via deeply nested messages",
        description="Proto2 messages with deeply nested submessages can cause stack overflow "
                    "during parsing when recursion depth is untracked.",
        affected_languages=["cpp", "java", "python", "go"],
        trigger_pattern="message Outer { message Inner { message Deep { ... } } }",
        detection_regex=r"message\s+\w+\s*\{",
    ),
    CVEPattern(
        id="PROTOBUF-UNKNOWN-FIELD-OVERFLOW",
        title="Memory exhaustion via unknown fields in InternalMetadata",
        description="Large unknown field sets in InternalMetadata can cause excessive memory "
                    "allocation without proper bounds checking.",
        affected_languages=["cpp"],
        trigger_pattern="Unknown field set with millions of entries",
        detection_regex=r"InternalMetadata|UnknownFieldSet",
    ),
]


def get_patterns(language: str | None = None) -> list[CVEPattern]:
    """Get CVE patterns, optionally filtered by target language."""
    if language is None:
        return PATTERNS
    return [p for p in PATTERNS if language in p.affected_languages]


def get_pattern_by_id(pattern_id: str) -> CVEPattern | None:
    """Look up a pattern by its ID."""
    return next((p for p in PATTERNS if p.id == pattern_id), None)
