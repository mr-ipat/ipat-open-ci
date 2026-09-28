#!/usr/bin/env python3
"""Independently encode BBF v1.4 USP NO SESSION Get and GetResp goldens.
NO Google/prost code, private networks, real device fields or live transports.
Fields cross-checked against BroadbandForum/usp's published 1.4 schemas.
"""
import argparse
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[4] / "crates/usp-core/tests/fixtures"

def vint(value):
    assert isinstance(value, int) and value >= 0
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)

def binary(tag, payload):
    return vint(tag * 8 + 2) + vint(len(payload)) + payload

def string(tag, value):
    return binary(tag, value.encode("utf-8"))

def integer(tag, value):
    return vint(tag * 8) + vint(value)

def golden(response=False, msg_id="r-example-1"):
    destination = "usp::offline-controller" if response else "usp::sim-agent-a"
    sender = "usp::sim-agent-a" if response else "usp::offline-controller"
    head = string(1, msg_id) + integer(2, 2 if response else 1)
    if response:
        entry = string(1, "Manufacturer") + string(2, "SYNTHETIC")
        resolved = string(1, "Device.DeviceInfo.") + binary(2, entry)
        requested = string(1, "Device.DeviceInfo.") + binary(4, resolved)
        content = binary(2, binary(1, binary(1, requested)))
    else:
        get = string(1, "Device.DeviceInfo.")
        content = binary(1, binary(1, get))
    msg = binary(1, head) + binary(2, content)
    # Record.version=1, to_id=2, from_id=3; no-session oneof=7
    # and NoSessionContextRecord.payload=2 (both defined by the BBF).
    return (string(1, "1.4") + string(2, destination)
            + string(3, sender) + binary(7, binary(2, msg)))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--write", action="store_true")
    args = p.parse_args()
    for name, content in [
        ("usp14_get_request.bin", golden(False)),
        ("usp14_get_response.bin", golden(True)),
        ("usp14_get_response_correlated.bin", golden(True, "r1")),
    ]:
        path = BASE / name
        if args.write:
            if path.exists():
                if path.read_bytes() != content:
                    raise SystemExit("REFUSE_OVERWRITE_GOLDEN: " + str(path))
            else:
                path.write_bytes(content)
        else:
            if not path.is_file() or path.read_bytes() != content:
                raise SystemExit("GOLDEN_FIXTURE_MISMATCH: " + name)
        print("USP14_INDEPENDENT_MANUAL_GOLDEN_OK", name, len(content))
if __name__ == "__main__":
    main()
