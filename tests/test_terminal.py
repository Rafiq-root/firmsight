import io

from firmsight.terminal import run_tui


def test_tui_dashboard_quits_with_case_summary(tmp_path):
    firmware = tmp_path / "router.bin"
    firmware.write_bytes(b"sample")
    output = io.StringIO()
    result = run_tui(firmware, tmp_path / "case", input_fn=lambda _prompt: "q", output=output)
    assert result == 0
    assert "FirmSight · case dashboard" in output.getvalue()
    assert "SHA-256:" in output.getvalue()
    assert "Boot with networking disabled" in output.getvalue()


def test_tui_streams_action_through_runner(tmp_path):
    firmware = tmp_path / "router.bin"
    firmware.write_bytes(b"sample")
    output = io.StringIO()
    calls = []

    def runner(command, stream):
        calls.append(command)
        stream.write("scan complete\n")
        return 0

    choices = iter(("i", "q"))
    run_tui(firmware, tmp_path / "case", input_fn=lambda _prompt: next(choices), output=output, runner=runner)
    assert "scan complete" in output.getvalue()
    assert calls[0][1:4] == ["-u", "-m", "firmsight.cli"]
