import io
import tempfile
import unittest
from pathlib import Path

from check_local_paths import check_files, finding_lines


# Construct private-looking examples so the tests themselves pass the scanner.
class LocalPathTests(unittest.TestCase):
    def test_personal_paths(self):
        paths = [
            "/home/" + "alice/project",
            "/Users/" + "alice/project",
            "C:" + r"\Users\Alice\project",
            "D:/Users/" + "Alice/project",
            "C:" + r"\Documents and Settings\Alice\project",
            "/mnt/c/" + "Users/Alice/project",
            r"\\wsl$" + r"\Ubuntu\home\alice\project",
            r"\\wsl.localhost" + r"\Ubuntu\home\alice\project",
            "file://" + "/home/" + "alice/project",
        ]
        for path in paths:
            for value in (path, path.replace("\\", "\\\\")):
                with self.subTest(value=value):
                    self.assertEqual(finding_lines(("intro\n`" + value + "`\n").encode()), [2])

    def test_portable_examples(self):
        for value in [
            "../outgate-sdk/", "docs/requirements.md", "../home/alice/file",
            "/etc/outgate/config.yaml", "/var/lib/outgate", "/tmp/example",
            "/home/<user>/project", "/Users/${USER}/project",
            "C:/Users/<username>/project", r"C:\Users\%USERNAME%\project",
            "/home/$USER/project", "/home/{user}/project",
            "https://example.org/home/alice/project",
            "https://github.com/example/repo/blob/main/Users/alice/file",
        ]:
            with self.subTest(value=value):
                self.assertEqual(finding_lines(value.encode()), [])

    def test_url_does_not_hide_next_path(self):
        value = "https://example.org/home/alice then /home/" + "bob/private"
        self.assertEqual(finding_lines(value.encode()), [1])

    def test_binary(self):
        self.assertEqual(finding_lines(b"\0/home/" + b"alice/project"), [])

    def test_diagnostics_and_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = "/home/" + "alice/private"
            (root / "notes.md").write_text("intro\n" + private + "\n", encoding="utf-8")
            output = io.StringIO()
            self.assertEqual(check_files(root, ["notes.md"], output), 1)
            self.assertIn("notes.md:2:", output.getvalue())
            self.assertNotIn(private, output.getvalue())
            self.assertNotIn("alice", output.getvalue())
            (root / "notes.md").write_text("../outgate-sdk/\n", encoding="utf-8")
            self.assertEqual(check_files(root, ["notes.md", "deleted.md"], io.StringIO()), 0)


if __name__ == "__main__":
    unittest.main()
