"""Exercise Unicode test output with a Windows-style redirected code page."""
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("go_test_runner", Path(__file__).with_name("run_go_tests.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class Process:
    def __init__(self, lines):
        self.stdout = lines
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def wait(self):
        return 0


class UnicodeOutputTest(unittest.TestCase):
    def test_redirected_windows_codepage_keeps_unicode_output(self):
        text = "=== RUN TestMount/отчёты\n"
        output = io.BytesIO()
        stream = io.TextIOWrapper(output, encoding="cp1252", errors="strict")
        lines = [json.dumps({"Action": "output", "Output": text}, ensure_ascii=False) + "\n"]
        try:
            with patch.object(runner.sys, "stdout", stream), patch.object(runner.subprocess, "Popen", return_value=Process(lines)):
                self.assertEqual(runner.main(), 0)
            stream.flush()
            self.assertEqual(output.getvalue().decode("utf-8"), text)
        finally:
            stream.close()


if __name__ == "__main__":
    unittest.main()
