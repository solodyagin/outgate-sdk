"""Verify failure propagation, bounded diagnostics and explicit check scopes."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("local_checks", Path(__file__).with_name("check.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CheckRunnerTest(unittest.TestCase):
    def test_success_keeps_full_log_without_console_flood(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            log = root / "step.log"
            console = io.StringIO()
            env = dict(os.environ, CHECK_RUNNER_SENTINEL="present")
            command = [sys.executable, "-c",
                       "import os,sys; print(os.getcwd()); print(os.environ['CHECK_RUNNER_SENTINEL']); "
                       "print('x' * 20000); print('stderr-sentinel', file=sys.stderr)"]
            with contextlib.redirect_stdout(console):
                code = runner.run_step("success", root, command, log, env)
            self.assertEqual(code, 0)
            self.assertLess(len(console.getvalue()), 200)
            data = log.read_text()
            self.assertIn(str(root), data)
            self.assertIn("present", data)
            self.assertIn("stderr-sentinel", data)
            self.assertGreater(len(data), 20000)

    def test_failure_keeps_exit_code_and_bounded_utf8_diagnostics(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "step.log"
            console = io.StringIO()
            command = [sys.executable, "-c",
                       "import sys; sys.stdout.buffer.write(b'x' * 30000 + "
                       "'\\nошибка\\n'.encode('utf-8')); sys.exit(7)"]
            with contextlib.redirect_stdout(console):
                code = runner.run_step("failure", Path(folder), command, log, os.environ)
            self.assertEqual(code, 7)
            self.assertIn("ошибка", console.getvalue())
            self.assertLess(len(console.getvalue()), 9000)
            self.assertGreater(log.stat().st_size, 30000)

    def test_missing_program_is_a_failure_with_log(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "step.log"
            with contextlib.redirect_stdout(io.StringIO()):
                code = runner.run_step("missing", Path(folder),
                                       [str(Path(folder) / "absent-command")], log, os.environ)
            self.assertNotEqual(code, 0)
            self.assertTrue(log.read_bytes())

    def test_main_stops_after_failure_and_forces_workspace_off(self):
        output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(runner.tempfile, "mkdtemp", return_value=folder), \
                 patch.object(runner.sys, "stdout", output), \
                 patch.object(runner, "run_step", return_value=7) as run:
                self.assertEqual(runner.main(["package", "./example"]), 1)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.args[-1]["GOWORK"], "off")
        output.close()

    def test_package_scope_is_explicit_and_contracts_do_not_run_go(self):
        package = runner.plan("package", ["./example"])
        self.assertEqual(len(package), 2)
        self.assertTrue(all(step[2][-1] == "./example" for step in package))
        self.assertTrue(all(step[2][0] == sys.executable
                            for step in runner.plan("contracts", [])))
        full = runner.plan("full", [])
        self.assertTrue(any(step[2] == ["go", "mod", "verify"] for step in full))
        self.assertTrue(any(step[2] == ["go", "vet", "./..."] for step in full))


if __name__ == "__main__":
    unittest.main()
