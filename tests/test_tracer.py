
import pytest

from firmsight.core import FirmSightError
from firmsight.tracer import create_gdb_trace


def test_gdb_trace_script_logs_function_hits_and_crash_paths(tmp_path):
    command, script, output = create_gdb_trace(
        "127.0.0.1:1234", ["handle_request", "*0x401000"],
        tmp_path / "trace.log", symbols=None, gdb_binary="gdb-multiarch",
    )
    contents = script.read_text()
    assert command[-2:] == ["-x", str(script)]
    assert output == (tmp_path / "trace.log").resolve()
    assert "break handle_request" in contents
    assert "[HIT] *0x401000" in contents
    assert "[CRASH PATH] panic" in contents


def test_gdb_trace_rejects_command_injection_in_function(tmp_path):
    with pytest.raises(FirmSightError, match="Invalid function"):
        create_gdb_trace("127.0.0.1:1234", ["panic; quit"], tmp_path / "trace.log", gdb_binary="gdb")
