"""Parse .proto files to extract message types and field structure."""

import re
from dataclasses import dataclass, field


@dataclass
class ProtoField:
    name: str
    type: str
    number: int
    repeated: bool = False
    optional: bool = False


@dataclass
class ProtoMessage:
    name: str
    fields: list[ProtoField] = field(default_factory=list)
    nested_messages: list["ProtoMessage"] = field(default_factory=list)
    nesting_depth: int = 0


@dataclass
class ProtoFile:
    syntax: str = "proto3"
    package: str = ""
    messages: list[ProtoMessage] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    file_path: str = ""


_FIELD_RE = re.compile(
    r"^\s*(optional|required|repeated)?\s*"
    r"(map<[^>]+>|[\w.]+)\s+"
    r"(\w+)\s*=\s*(\d+)\s*;"
)
_MESSAGE_RE = re.compile(r"^\s*message\s+(\w+)\s*\{")
_SYNTAX_RE = re.compile(r'^\s*syntax\s*=\s*"(\w+)"')
_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;")
_IMPORT_RE = re.compile(r'^\s*import\s+"([^"]+)"\s*;')


def parse_proto(content: str, file_path: str = "") -> ProtoFile:
    """Parse a .proto file's content into structured types."""
    result = ProtoFile(file_path=file_path)
    lines = content.split("\n")

    message_stack: list[ProtoMessage] = []
    brace_depth = 0

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        if m := _SYNTAX_RE.match(stripped):
            result.syntax = m.group(1)
            continue
        if m := _PACKAGE_RE.match(stripped):
            result.package = m.group(1)
            continue
        if m := _IMPORT_RE.match(stripped):
            result.imports.append(m.group(1))
            continue

        brace_depth += stripped.count("{") - stripped.count("}")

        if m := _MESSAGE_RE.match(stripped):
            msg = ProtoMessage(name=m.group(1), nesting_depth=len(message_stack))
            if message_stack:
                message_stack[-1].nested_messages.append(msg)
            else:
                result.messages.append(msg)
            message_stack.append(msg)
            continue

        if brace_depth <= 0:
            message_stack.clear()
            brace_depth = 0
            continue

        if message_stack and (m := _FIELD_RE.match(stripped)):
            current = message_stack[-1]
            label = m.group(1)
            current.fields.append(
                ProtoField(
                    name=m.group(3),
                    type=m.group(2),
                    number=int(m.group(4)),
                    repeated=label == "repeated",
                    optional=label == "optional",
                )
            )

    return result


def max_nesting_depth(proto: ProtoFile) -> int:
    """Return the maximum message nesting depth in the file."""
    def _depth(messages: list[ProtoMessage]) -> int:
        if not messages:
            return 0
        return max(m.nesting_depth + _depth(m.nested_messages) for m in messages) if messages else 0
    return _depth(proto.messages)


def has_recursive_refs(proto: ProtoFile) -> list[tuple[str, str]]:
    """Find messages whose fields reference themselves (direct recursion)."""
    recursions: list[tuple[str, str]] = []
    for msg in proto.messages:
        for f in msg.fields:
            if f.type == msg.name:
                recursions.append((msg.name, f.name))
    return recursions
