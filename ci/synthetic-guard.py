#!/usr/bin/env python3
"""Public snapshot release gate: no actual live site IP or PEM private keys."""
import ipaddress
import re
import subprocess
from pathlib import Path

paths=subprocess.check_output(['git','ls-files','-z']).decode().split('\0')
problems=[]
for name in filter(None,paths):
    path=Path(name)
    if not path.is_file():continue
    try:doc=path.read_text(encoding='utf8')
    except UnicodeDecodeError:continue
    if re.search(r'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----',doc):
        problems.append((name,'embedded-private-key'))
    if re.search(r'github_pat_[a-zA-Z0-9_]{35,}|gh[pousr]_[a-zA-Z0-9]{30,}',doc):
        problems.append((name,'embedded-gh-token'))
    if re.search(r'(?<![\w])(?:10\.10\.13\.|110\.232\.|27\.121\.)',doc):
        problems.append((name,'operational-network-subnet'))
    for val in re.findall(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)',doc):
        try:ip=ipaddress.ip_address(val)
        except ValueError:continue
        if ip.version==4 and ip.is_global and not ip.is_multicast and not ip.is_private:
            if val not in ('1.1.1.1','8.8.8.8','8.8.4.4'):
                problems.append((name,'non-synthetic-global-ip'))
if problems:
    print('PUBLIC_SANITIZATION_AUDIT_FAILED:', sorted(set(problems))[:12])
    raise SystemExit(4)
print('PUBLIC_SANITIZATION_AUDIT_PASSED: synthetic snapshot only')
