#!/usr/bin/env python3
"""Binary-safe Mac SSH->Restic stream. Never persist Linux sudo password.

Use ONLY as the --stdin-from-command producer for Restic, invoked by the
reviewed mac-root-config-backup.sh. --smoke and --fail-smoke are unprivileged
fixture modes for end-to-end testing. --root requires an interactive Mac tty.
"""
from __future__ import annotations

import getpass
import os
import shlex
import shutil
import subprocess
import sys

ROOT_TAR = r"""
set -Eeuo pipefail
umask 077
test "$(id -u)" = 0
source /etc/os-release
test "$ID" = ubuntu && test "$VERSION_ID" = 26.04
test -f /etc/ssh/sshd_config
test -f /etc/ssh/sshd_config.d/00-ipat-lab-hardening.conf
test -s /home/openai/.ssh/authorized_keys
required=(
  etc/os-release
  etc/fstab
  etc/ssh/sshd_config
  etc/ssh/sshd_config.d
  etc/sudoers
  home/openai/.ssh/authorized_keys
)
optional=(
  etc/sudoers.d
  etc/apt/sources.list.d
  etc/cloud/cloud.cfg.d
  etc/netplan
  etc/systemd/network
)
for path in "${optional[@]}"; do
    if [[ -e "/$path" || -L "/$path" ]]; then
        required+=("$path")
    fi
done
# Exclude SSH host PRIVATE KEYS intentionally: a separate custody and
# host-rekey design needs independent review.
exec /usr/bin/tar -C / --one-file-system --numeric-owner --acls --xattrs \
    -czf - -- "${required[@]}"
"""

SSH_BASE = [
    "/usr/bin/ssh", "-T", "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes", "-o", "ControlMaster=no",
    "-o", "ControlPath=none", "-o", "ConnectTimeout=10",
    "-o", "PreferredAuthentications=publickey",
    "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
    "ipat-lab",
]


def run(mode: str) -> int:
    if sys.platform != "darwin":
        print("ABORT: run on authorized Mac only", file=sys.stderr)
        return 2
    if mode == "--root":
        try:
            with open("/dev/tty", "rb") as terminal:
                if not os.isatty(terminal.fileno()):
                    print("ABORT: no interactive Mac Terminal", file=sys.stderr)
                    return 3
        except OSError:
            print("ABORT: interactive Mac Terminal required", file=sys.stderr)
            return 3
        # Human input is sent only through encrypted SSH stdin, never stdout,
        # argv, environment, disk, repository, or tool-generated responses.
        # Restic may redraw its progress line over a subprocess getpass prompt.
        # Use the controlling TTY directly; never print a secret or prompt into
        # the encrypted stdout stream.
        with open("/dev/tty", "w", encoding="utf-8") as terminal:
            terminal.write("\nIPAT: masukkan password SUDO Linux untuk user openai.\n")
            terminal.write("BUKAN password/passphrase SSH dan BUKAN login root.\n")
            terminal.flush()
        pwd = getpass.getpass("Password sudo openai (tidak tampil saat diketik): ")
        if not pwd:
            print("ABORT: blank sudo password", file=sys.stderr)
            return 3
        remote = "sudo -S -k -p '' /bin/bash -c " + shlex.quote(ROOT_TAR)
        args = SSH_BASE + [remote]
        child_in = subprocess.PIPE
    elif mode == "--smoke":
        args = SSH_BASE + ["tar -C / -czf - etc/os-release etc/ssh/sshd_config"]
        pwd = None
        child_in = subprocess.DEVNULL
    elif mode == "--fail-smoke":
        # Verify restic discards partial output when an SSH producer fails.
        args = SSH_BASE + ["printf '\\037\\213'; exit 42"]
        pwd = None
        child_in = subprocess.DEVNULL
    else:
        print("usage: root-config-stream.py --root|--smoke|--fail-smoke",
              file=sys.stderr)
        return 2

    proc = subprocess.Popen(args, stdin=child_in, stdout=subprocess.PIPE)
    try:
        if pwd is not None:
            assert proc.stdin is not None
            proc.stdin.write((pwd + "\n").encode("utf-8"))
            proc.stdin.flush()
            proc.stdin.close()
            del pwd
        assert proc.stdout is not None
        first = proc.stdout.read(2)
        if first != b"\x1f\x8b":
            print("ABORT: SSH producer did not output a gzip tar stream", file=sys.stderr)
            proc.stdout.close()
            proc.wait(timeout=15)
            return 5
        sys.stdout.buffer.write(first)
        shutil.copyfileobj(proc.stdout, sys.stdout.buffer, length=128 * 1024)
        sys.stdout.buffer.flush()
        proc.stdout.close()
        rc = proc.wait(timeout=120)
        if rc:
            print(f"ABORT: SSH/tar producer failed (exit {rc}); restic must discard snapshot",
                  file=sys.stderr)
            return 6
        return 0
    except (BrokenPipeError, OSError, subprocess.TimeoutExpired) as exc:
        proc.kill()
        proc.wait()
        print(f"ABORT: binary stream failed: {type(exc).__name__}", file=sys.stderr)
        return 7


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: root-config-stream.py --root|--smoke|--fail-smoke",
              file=sys.stderr)
        sys.exit(2)
    sys.exit(run(sys.argv[1]))
