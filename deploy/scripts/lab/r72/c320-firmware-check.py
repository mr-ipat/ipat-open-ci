#!/usr/bin/env python3
"""IPAT DEV-01 local-only firmware file hash check. NEVER upgrades an OLT.

Do not confuse an operator-copied checksum with independent vendor provenance.
A successful exit is ONLY an integrity arithmetic result on a private file.
"""
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

MAX_IMAGE_BYTES = 1024 * 1024 * 1024
MAX_METADATA_BYTES = 8192
ALLOWED_KIND = {"software", "firmware", "patch"}
FIELDS = {"target_id", "vendor", "model", "card_type",
          "image_kind", "target_version", "release_reference"}

def deny(reason):
    print("R72_BLOCKED=" + reason, file=sys.stderr)
    raise SystemExit(4)

def private_directory(raw):
    path = Path(raw)
    if not path.is_absolute() or any(x in (".", "..") for x in path.parts):
        deny("UNTRUSTED_DIRECTORY")
    try:
        meta = path.lstat()
    except OSError:
        deny("MISSING_DIRECTORY")
    if (not stat.S_ISDIR(meta.st_mode) or stat.S_ISLNK(meta.st_mode)
            or meta.st_uid != os.geteuid() or stat.S_IMODE(meta.st_mode) != 0o700):
        deny("UNTRUSTED_DIRECTORY")
    return path

def open_private_file(parent, name, limit):
    path = parent / name
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode)
                or stat.S_ISLNK(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or not 0 < before.st_size <= limit):
            deny("UNTRUSTED_FILE")
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        after = os.fstat(fd)
        if (not stat.S_ISREG(after.st_mode)
                or after.st_dev != before.st_dev
                or after.st_ino != before.st_ino
                or after.st_uid != os.geteuid()
                or stat.S_IMODE(after.st_mode) != 0o600
                or after.st_nlink != 1
                or not 0 < after.st_size <= limit):
            os.close(fd)
            deny("FILE_CHANGED")
        return os.fdopen(fd, "rb")
    except OSError:
        deny("FILE_UNAVAILABLE")

def bounded_read(parent, name):
    with open_private_file(parent, name, MAX_METADATA_BYTES) as stream:
        data = stream.read(MAX_METADATA_BYTES + 1)
    if len(data) > MAX_METADATA_BYTES:
        deny("UNSAFE_METADATA")
    return data

def load_metadata(parent):
    try:
        data = json.loads(bounded_read(parent, "plan.json"))
    except (UnicodeError, ValueError):
        deny("INVALID_PLAN")
    if not isinstance(data, dict) or set(data) != FIELDS:
        deny("INVALID_PLAN_FIELDS")
    if (data["target_id"] != "DEV-01" or data["vendor"] != "ZTE"
            or data["model"] != "ZXA10 C320"
            or data["image_kind"] not in ALLOWED_KIND):
        deny("WRONG_DEVICE_PROFILE")
    for name, maximum in (("card_type", 32), ("target_version", 64),
                          ("release_reference", 128)):
        value = data[name]
        if (not isinstance(value, str) or not (1 <= len(value) <= maximum)
                or not re.fullmatch(r"[A-Za-z0-9_.:/-]+", value)
                or ".." in value or value.startswith("/")):
            deny("UNVERIFIED_RELEASE_METADATA")
    # These fields are provided by an operator. They never assert hardware
    # compatibility or authenticate a firmware file's vendor origin.
    return data

def read_claimed_checksum(parent):
    try:
        line = bounded_read(parent, "vendor.sha256").decode("ascii")
    except UnicodeError:
        deny("INVALID_CHECKSUM_FILE")
    if not re.fullmatch(r"[a-fA-F0-9]{64}  image.bin\n?", line):
        deny("INVALID_CHECKSUM_FILE")
    return line[:64].lower()

def hash_private_image(parent):
    digest = hashlib.sha256()
    count = 0
    with open_private_file(parent, "image.bin", MAX_IMAGE_BYTES) as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            count += len(block)
            if count > MAX_IMAGE_BYTES:
                deny("IMAGE_TOO_LARGE")
            digest.update(block)
    return digest.hexdigest()

def main(argv):
    if argv == ["--requirements"]:
        print("R72_ONLY_OFFLINE_SHA256_CHECK_NO_DEVICE_ACCESS_NO_FIRMWARE_EXECUTION")
        print("REQUIRES_OPERATOR_PRIVATE_DIR_0700;plan.json,kind=image.bin,vendor.sha256_0600")
        print("VENDOR_HASH_SOURCE_INDEPENDENTLY_VERIFIED=NOT_ESTABLISHED_BY_THIS_TOOL")
        return 0
    if len(argv) != 2 or argv[0] != "--check":
        deny("EXPLICIT_LOCAL_CHECK_REQUIRED")
    if os.getenv("IPAT_R72_APPROVE_OFFLINE_HASH_ONLY") != "YES":
        deny("EXPLICIT_HASH_ONLY_OPT_IN_REQUIRED")
    if os.geteuid() == 0:
        deny("ROOT_NOT_PERMITTED")
    parent = private_directory(argv[1])
    plan = load_metadata(parent)
    claimed = read_claimed_checksum(parent)
    actual = hash_private_image(parent)
    if actual != claimed:
        deny("IMAGE_DIGEST_MISMATCH")
    # Deliberately do not expose model- or card-specific "supported" flags,
    # vendor authenticity or a method to unlock any remote firmware command.
    print(json.dumps({
        "target_id": plan["target_id"],
        "local_sha256_equals_operator_supplied_checksum": True,
        "vendor_release_authenticity_independently_proven": False,
        "actual_c320_board_compatibility_verified": False,
        "physical_recovery_and_approvals_verified": False,
        "firmware_upgrade_enabled": False,
        "disposition": "HUMAN_REVIEW_ONLY_NOT_EXECUTABLE"
    }, separators=(",", ":"), sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
