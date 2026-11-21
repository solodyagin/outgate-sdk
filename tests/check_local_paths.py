#!/usr/bin/env python3
"""Reject personal home paths in tracked text files; standard library only."""

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REMOTE_URL = re.compile(r'\b(?:https?|ssh|git)://[^\s<>"`]+', re.IGNORECASE)
HOME_PATH = re.compile(
    r"(?<![\w./\\:-])(?:file://)?(?:"
    r"/(?:home|Users)/"
    r"|[a-z]:[/\\]+(?:Users|Documents and Settings)[/\\]+"
    r"|/mnt/[a-z]/Users/"
    r"|\\{2,}wsl(?:\$|\.localhost)\\+[^\\\s]+\\+home\\+"
    r")(?P<user><[^<>/\\\r\n]+>|\$\{[^}\r\n]+\}|\{[^}\r\n]+\}"
    r"|[^\s/\\`\"'<>]+)",
    re.IGNORECASE,
)
PLACEHOLDER = re.compile(r"(?:<[^<>]+>|\$?\{[^{}]+\}|\$[A-Z_][A-Z_0-9]*|%[A-Z_][A-Z_0-9]*%)\Z")


def finding_lines(data):
    """Return line numbers only, never the matched private text."""
    if b"\0" in data:
        return []  # Git-style binary heuristic.
    findings = []
    for number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
        line = REMOTE_URL.sub("", line)
        if any(not PLACEHOLDER.fullmatch(match["user"])
               for match in HOME_PATH.finditer(line)):
            findings.append(number)
    return findings


def check_files(root, paths, output):
    failed = False
    for relative in paths:
        path = root / relative
        try:
            if path.is_symlink():
                # Check the published link target, not files outside the repository.
                data = str(path.readlink()).encode("utf-8")
            else:
                data = path.read_bytes()
        except FileNotFoundError:
            continue  # Tracked file deleted in the working tree.
        except OSError:
            print(f"{relative}: cannot read tracked file", file=output)
            failed = True
            continue
        for number in finding_lines(data):
            print(f"{relative}:{number}: personal home path; use a relative path or placeholder",
                  file=output)
            failed = True
    return 1 if failed else 0


def main():
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, check=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        print("Cannot list tracked files with git", file=sys.stderr)
        return 1
    paths = [name.decode("utf-8", errors="surrogateescape")
             for name in result.stdout.split(b"\0") if name]
    status = check_files(ROOT, paths, sys.stderr)
    if not status:
        print("Local path check: PASS")
    return status


if __name__ == "__main__":
    sys.exit(main())
