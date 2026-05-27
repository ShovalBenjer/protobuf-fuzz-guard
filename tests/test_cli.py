"""Tests for CLI."""

import json
from pathlib import Path

from protobuf_fuzz_guard.cli import main


def test_patterns_command(capsys):
    exit_code = main(["patterns"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "CVE-2024-7254" in captured.out
    assert "TYPE_GROUP" in captured.out


def test_scan_clean_proto(tmp_path, capsys):
    proto_file = tmp_path / "clean.proto"
    proto_file.write_text("message Simple { string name = 1; }")
    exit_code = main(["scan", str(proto_file)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "No findings" in captured.out


def test_scan_risky_proto(tmp_path, capsys):
    proto_file = tmp_path / "risky.proto"
    proto_file.write_text("""
    message Node {
        Node child = 1;
    }
    """)
    exit_code = main(["scan", str(proto_file)])
    assert exit_code == 1  # critical findings


def test_scan_json_output(tmp_path, capsys):
    proto_file = tmp_path / "msg.proto"
    proto_file.write_text("message Msg { string v = 1; }")
    exit_code = main(["scan", str(proto_file), "--json"])
    captured = capsys.readouterr()
    assert exit_code == 0
    data = json.loads(captured.out)
    assert isinstance(data, list)


def test_generate_command(tmp_path, capsys):
    proto_file = tmp_path / "msg.proto"
    proto_file.write_text("""
    syntax = "proto3";
    message Person { string name = 1; }
    """)
    out_dir = tmp_path / "output"
    exit_code = main(["generate", str(proto_file), "-o", str(out_dir), "-l", "python"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert (out_dir / "python" / "fuzz_person.py").exists()
