"""Compare the native SDK test imports with the pinned dependency SBOM."""
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def go(*args):
    return subprocess.check_output(
        ["go", *args], cwd=ROOT, encoding="utf-8",
        env=os.environ | {"GOWORK": "off", "CGO_ENABLED": "0"},
    ).splitlines()


def main():
    os_name, architecture, go_version = go("env", "GOOS", "GOARCH", "GOVERSION")
    platform = f"{os_name}/{architecture}"
    if platform not in {"linux/amd64", "windows/amd64"}:
        raise ValueError(f"Dependency SBOM does not cover {platform}")

    bom = json.loads((ROOT / "docs" / "sbom.cdx.json").read_text(encoding="utf-8"))
    actual = {
        tuple(line.split())
        for line in go("list", "-mod=readonly", "-deps", "-test", "-f",
                       "{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}", "./...")
        if line.strip()
    }
    expected = {
        (component["name"], component["version"]): component
        for component in bom["components"]
        if component.get("purl", "").startswith("pkg:golang/") and
        {"name": "outgate:platform", "value": platform} in component["properties"]
    }
    if actual != expected.keys():
        raise ValueError(f"{platform} module inventory differs: missing {actual - expected.keys()}, "
                         f"stale {expected.keys() - actual}")
    sums = {}
    for line in (ROOT / "go.sum").read_text(encoding="utf-8").splitlines():
        module, version, checksum = line.split()
        sums[module, version] = checksum
    for key, component in expected.items():
        if {"name": "outgate:go:sum", "value": sums.get(key)} not in component["properties"]:
            raise ValueError(f"SBOM checksum differs for {' '.join(key)}")
    if not any(component.get("purl") == f"pkg:generic/go-stdlib@{go_version.removeprefix('go')}"
               for component in bom["components"]):
        raise ValueError("Go standard library version differs from SBOM")
    print(f"SBOM: {len(actual)} pinned Go dependencies match {platform}")


if __name__ == "__main__":
    main()
