"""Scan .proto files for known CVE patterns and structural risks."""

from dataclasses import dataclass

from .models import CVEPattern, get_patterns
from .proto_parser import ProtoFile, max_nesting_depth, has_recursive_refs


@dataclass
class Finding:
    severity: str  # "critical" | "warning" | "info"
    pattern: CVEPattern | None
    message: str
    file_path: str
    line: int | None = None


def scan(proto: ProtoFile) -> list[Finding]:
    """Scan a parsed .proto file for CVE patterns and structural risks."""
    findings: list[Finding] = []

    depth = max_nesting_depth(proto)
    if depth >= 5:
        findings.append(Finding(
            severity="critical",
            pattern=get_patterns()[2],  # recursion pattern
            message=f"Message nesting depth {depth} exceeds safe threshold (5). "
                    f"Vulnerable to stack overflow via deeply nested parsing.",
            file_path=proto.file_path,
        ))
    elif depth >= 3:
        findings.append(Finding(
            severity="warning",
            pattern=None,
            message=f"Message nesting depth {depth} is moderate. "
                    f"Consider adding recursion depth limits in generated harnesses.",
            file_path=proto.file_path,
        ))

    recursions = has_recursive_refs(proto)
    for msg_name, field_name in recursions:
        findings.append(Finding(
            severity="critical",
            pattern=get_patterns()[2],
            message=f"Recursive message reference: {msg_name}.{field_name} references itself. "
                    f"Vulnerable to unbounded recursion attacks.",
            file_path=proto.file_path,
        ))

    for msg in proto.messages:
        for f in msg.fields:
            if f.type in ("group", "TYPE_GROUP"):
                findings.append(Finding(
                    severity="critical",
                    pattern=get_patterns()[0],  # CVE-2024-7254 class
                    message=f"Field {msg.name}.{f.name} uses deprecated TYPE_GROUP. "
                            f"Known CVE surface (CVE-2024-7254 class). Replace with nested message.",
                    file_path=proto.file_path,
                ))

    repeated_nested = [
        (m.name, f.name)
        for m in proto.messages
        for f in m.fields
        if f.repeated and any(n.name == f.type for n in proto.messages)
    ]
    for msg_name, field_name in repeated_nested:
        findings.append(Finding(
            severity="warning",
            pattern=None,
            message=f"Repeated nested message: {msg_name}.{field_name}. "
                    f"Can cause memory exhaustion without size limits.",
            file_path=proto.file_path,
        ))

    for msg in proto.messages:
        bytes_fields = [f for f in msg.fields if f.type == "bytes" and f.repeated]
        if len(bytes_fields) >= 3:
            findings.append(Finding(
                severity="warning",
                pattern=get_patterns()[3],  # unknown field overflow
                message=f"{msg.name} has {len(bytes_fields)} repeated bytes fields. "
                        f"Potential for memory exhaustion via large payloads.",
                file_path=proto.file_path,
            ))

    return findings
