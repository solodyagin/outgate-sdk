#!/usr/bin/env python3
"""Run explicit local check scopes with bounded console output and full logs."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ['tests/fixtures/protocol/v1/verify.py', 'tests/fixtures/discovery/v1/verify.py']
SMOKE = False


def plan(scope, packages):
    steps = []

    def add(name, command, cwd=ROOT):
        steps.append((name, cwd, command))

    def python(name, script):
        add(name, [sys.executable, "-B", script])

    if scope in ("contracts", "full"):
        for script in CONTRACTS:
            python(script, script)
    if scope == "full":
        add("Python tests", [sys.executable, "-B", "-m", "unittest", "discover",
                             "-s", "tests", "-p", "test_*.py"])
        python("Tracked local paths", "tests/check_local_paths.py")
        add("Module integrity", ["go", "mod", "verify"])
        python("SBOM", "tests/verify_sbom.py")
    if scope in ("package", "full"):
        targets = packages if scope == "package" else ["./..."]
        race = ["-race"] if sys.platform == "linux" else []
        add("Go tests", ["go", "test", *race, *targets])
        add("Go vet", ["go", "vet", *targets])
    if scope == "full" and SMOKE:
        cwd = ROOT / "tests" / "dependencies"
        add("Pinned dependency tests", ["go", "test", "-mod=readonly", "./..."], cwd)
        add("Pinned dependency vet", ["go", "vet", "-mod=readonly", "./..."], cwd)
        add("Pinned dependency SBOM", [sys.executable, "-B", "verify_sbom.py"], cwd)
    return steps


def run_step(name, cwd, command, log, env):
    print(f"RUN  {name}", flush=True)
    with log.open("wb") as output:
        try:
            result = subprocess.run(command, cwd=cwd, env=env, stdout=output,
                                    stderr=subprocess.STDOUT)
            code = result.returncode
        except OSError as error:
            output.write(str(error).encode("utf-8", errors="replace"))
            code = 1
    print(f"{'PASS' if code == 0 else 'FAIL'} {name}", flush=True)
    if code:
        with log.open("rb") as output:
            output.seek(max(0, log.stat().st_size - 8192))
            tail = output.read().decode("utf-8", errors="replace")
        print("\n".join(tail.splitlines()[-20:]), flush=True)
        print(f"Full failure log: {log}", flush=True)
    return code


def main(argv=None):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scope", choices=("package", "contracts", "full"))
    parser.add_argument("packages", nargs="*")
    parser.add_argument("--plan", action="store_true", help="show commands without running")
    args = parser.parse_args(argv)
    if args.scope == "package":
        if not args.packages or any(not p.startswith("./") for p in args.packages):
            parser.error("package requires explicit relative Go packages, e.g. ./delivery")
    elif args.packages:
        parser.error("packages are only accepted with package scope")
    steps = plan(args.scope, args.packages)
    if args.plan:
        for name, cwd, command in steps:
            display = ["python" if c == sys.executable else c for c in command]
            print(f"{name}: cwd={cwd.relative_to(ROOT)}; {display!r}")
        return 0
    log_dir = Path(tempfile.mkdtemp(prefix=f"{ROOT.name}-checks-"))
    print(f"Full logs: {log_dir}", flush=True)
    env = dict(os.environ, GOWORK="off")
    for index, (name, cwd, command) in enumerate(steps, 1):
        step_env = env.copy()
        if cwd != ROOT:
            step_env["CGO_ENABLED"] = "0"
        code = run_step(name, cwd, command, log_dir / f"{index:02d}.log", step_env)
        if code:
            return 1
    print(f"PASS {len(steps)} local checks ({args.scope}); logs: {log_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
