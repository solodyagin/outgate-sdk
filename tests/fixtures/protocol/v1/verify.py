#!/usr/bin/env python3
"""Offline sanity checks for Outgate v1 reference vectors; no production adapter tests."""
import base64
import hashlib
import hmac
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def read(name):
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def check(condition, message):
    if not condition:
        raise ValueError(message)


def frame_valid(raw, maximum):
    if len(raw) < 16:
        return False
    version, kind, flags, stream, size = struct.unpack(">BBHQI", raw[:16])
    return (
        version == 1 and kind in (1, 2, 3, 4) and flags == 0 and stream > 0
        and 0 < size <= maximum and len(raw) == 16 + size
    )


def main():
    frames = read("wss-frames.json")
    for case in frames["cases"]:
        raw = bytes.fromhex(case["hex"])
        check(frame_valid(raw, frames["max_chunk_bytes"]) == case["valid"], case["name"])
        if case["valid"]:
            version, kind, flags, stream, size = struct.unpack(">BBHQI", raw[:16])
            check((version, kind, flags, str(stream)) == (
                case["version"], case["kind"], case["flags"], case["stream_id"]
            ), case["name"] + " fields")
            check(raw[16:].hex() == case["payload_hex"] and size == len(raw[16:]),
                  case["name"] + " payload")

    signature_file = read("signatures.json")
    field = signature_file["rfc_field_combination"]
    check(", ".join(field["lines"]) == field["canonical_value"], "RFC field combination")
    vectors = signature_file["vectors"]
    for case in vectors:
        label = case["label"]
        prefix = label + "="
        check(case["signature_input"].startswith(prefix), case["name"] + " label")
        params = case["signature_input"][len(prefix):]
        ordered = "(" + " ".join(json.dumps(c["name"]) for c in case["components"]) + ")"
        check(params.startswith(ordered + ";created="), case["name"] + " components")
        rebuilt = "\n".join(json.dumps(c["name"]) + ": " + c["value"]
                            for c in case["components"]) + '\n"@signature-params": ' + params
        check(rebuilt == case["signature_base"], case["name"] + " base")
        key = bytes.fromhex(case["key_hex"])
        digest = hmac.new(key, rebuilt.encode("utf-8"), hashlib.sha256).digest()
        check(hmac.compare_digest(digest.hex(), case["hmac_hex"]), case["name"] + " HMAC")
        expected = prefix + ":" + base64.b64encode(digest).decode("ascii") + ":"
        check(expected == case["signature"], case["name"] + " Signature")
        needle = json.dumps(case["negative_replace"]["field"]) + ": "
        lines = rebuilt.split("\n")
        lines = [needle + case["negative_replace"]["value"] if l.startswith(needle) else l
                 for l in lines]
        tampered = hmac.new(key, "\n".join(lines).encode("utf-8"), hashlib.sha256).digest()
        check(not hmac.compare_digest(digest, tampered), case["name"] + " tamper")
        values = {c["name"]: c["value"] for c in case["components"]}
        path, _, query = case["raw_request_uri"].partition("?")
        check(values["@path"] == path and values["@query"] == "?" + query,
              case["name"] + " raw URI")

    boot = read("quic-bootstrap.json")
    raw = bytes.fromhex(boot["bootstrap_hex"])
    check(raw[:8] == b"Outgate1" and raw[8] == boot["credential_kind"], "QUIC preface")
    length = int.from_bytes(raw[9:11], "big")
    check(1 <= length <= 4096 and raw[11:11 + length].decode() == boot["credential_utf8"],
          "QUIC credential")
    frame = raw[11 + length:]
    size = int.from_bytes(frame[:4], "big")
    check(0 < size <= 65536 and size == len(frame) - 4, "QUIC JSON length")
    check(frame.hex() == boot["frame_hex"] and frame[4:].hex() == boot["control_json_hex"],
          "QUIC frame bytes")
    check(json.loads(frame[4:]) == boot["register"], "QUIC register")

    schema = json.loads((ROOT / "docs/protocol.schema.json").read_text())
    message_types = {
        name for name, definition in schema["$defs"].items()
        if definition.get("properties", {}).get("type", {}).get("const") == name
    }
    examples = read("control-messages.json")
    check({m["type"] for m in examples["positive"]} == message_types,
          "One example per message type")
    fences = read("quic-quiescent-fence.json")
    for case in fences["positive"]:
        wire = case["control_json_utf8"].encode()
        check(json.loads(wire) == case["message"], case["name"] + " fence JSON")
        check((len(wire).to_bytes(4, "big") + wire).hex() == case["frame_hex"],
              case["name"] + " fence bytes")
        check(case["message"]["extensions"][fences["capability"]] == case["fence"],
              case["name"] + " fence value")
    for case in fences["negative"]:
        value = case["extensions"].get(fences["capability"])
        valid = (isinstance(value, str) and value.isascii() and value.isdecimal()
                 and (value == "0" or not value.startswith("0"))
                 and len(value) <= 20 and int(value) <= 18446744073709551615)
        check(not valid, case["name"] + " fence negative")
    # Full Draft 2020-12 validation is a separate JSON Schema validator step.
    print(f"PASS: {len(message_types)} message types covered; {len(frames['cases'])} WSS "
          f"frame cases; {len(vectors)} HMAC+tamper vectors; QUIC bootstrap bytes. "
          "No network/adapter integration tested.")


if __name__ == "__main__":
    main()
