"""Offline discovery fixture sanity checks; no authentication or network I/O."""
import json
import re
from pathlib import Path


def unique(pairs):
    out = {}
    for name, value in pairs:
        if name in out:
            raise ValueError("duplicate key")
        out[name] = value
    return out


def validate(raw):
    if not 0 < len(raw.encode("utf-8")) <= 65536:
        raise ValueError("body bound")
    data = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(data, dict) or set(data) != {"service_id", "route_revision", "mounts"}:
        raise ValueError("response fields")
    if not isinstance(data["service_id"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", data["service_id"]):
        raise ValueError("service id")
    rev = data["route_revision"]
    if not isinstance(rev, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", rev) or int(rev) > 2**64-1:
        raise ValueError("revision")
    mounts = data["mounts"]
    if not isinstance(mounts, dict) or len(mounts) > 32:
        raise ValueError("mounts")
    for name, mount in mounts.items():
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name) or not isinstance(mount, dict) or set(mount) != {"path", "path_mode"}:
            raise ValueError("mount fields")
        path = mount["path"]
        if not isinstance(path, str) or not 0 < len(path.encode("utf-8")) <= 8192 or not path.startswith("/") or path != "/" and path.endswith("/"):
            raise ValueError("prefix")
        if any(c.isspace() or ord(c) < 32 or 127 <= ord(c) <= 159 or c in "%?#\\" for c in path) or "//" in path or any(s in {".", ".."} for s in path.split("/")):
            raise ValueError("ambiguous prefix")
        if mount["path_mode"] not in {"preserve", "strip"}:
            raise ValueError("mode")
    return data


def main():
    fixtures = json.loads(Path(__file__).with_name("responses.json").read_text(encoding="utf-8"))
    for response in fixtures["positive"]:
        validate(json.dumps(response, ensure_ascii=False))
    for case in fixtures["negative"]:
        try:
            validate(case["json"])
        except (ValueError, TypeError, UnicodeError):
            continue
        raise ValueError("accepted negative " + case["name"])
    print("PASS: discovery response fixtures (structure/semantics only)")


if __name__ == "__main__":
    main()
