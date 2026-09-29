# IPAT public CI source mirror

This is an independently sanitized, synthetic-only code snapshot for public GitHub Actions.

The private owner repository, privileged operational runbooks, actual
device inventory, network endpoints, fingerprints, credentials and historical
Actions logs are NOT part of this public mirror. Addresses and identity
fixtures are synthetic and MUST NOT be used to operate production ISP devices.

Changes validated here require separate protected integration and owner-side
acceptance before operational adoption. No physical ZTE C320 interoperability
or firmware support is certified by synthetic CI.

GitHub OAuth used for this export lacks workflow scope. Owner must copy `ci/github-actions.yml` to `.github/workflows/ci.yml` using GitHub web UI with an authorized account to activate public free CI.

R9.18 synthetic-source refresh maps to protected source commit
`1a9c6d1fa577dfd146fe430d46c8cd792371d488`. New code includes
an OFFLINE C320 read-only transcript validator; no physical OLT
compatibility or actual subscriber data is included. CI workflow is
staged at `ci/github-actions.yml` pending owner authorization to place
it in the GitHub workflows directory. The original full restricted
release CI/DB recovery acceptance still runs separately in protected
infrastructure; this public workflow is synthetic-only.

R9.19 synthetic-only private source mapping:
`c5be331e8fc0ce34836d6b5056cc808120a55173`.
This snapshot adds the denied-by-default C320 action catalog and frontend;
no actual physical OLT credentials, source addresses or console-key
fingerprints are published. GitHub-hosted synthetic CI remains
unregistered until account owner grants the GitHub `workflow` scope.

Current R9.19 protected source SHA:
`6c9273644d38144ae6d341e1ca690c1c8ee76eea`.
This update includes only sanitized source code and synthetic lab
fixtures, not physical OLT evidence or management credentials.
The protected branch remains the operational source of truth and
public hosted Actions still require explicit workflow authorization.

R9.20 protected implementation SHA `1f1820bc5b49f644d331dea3b31e41e2868a1073`
adds an offline owner-asserted console RSA host-key pin generator and
synthetic unit tests. No real site console key or host identity is
included; a matching public key is not actual hardware adoption.

R9.21 protected source SHA `89ef532fe33666cf88a2f504c8967467d2e41f95`
adds an offline STRICT synthetic-only parser for the vendor's historic
`show ssh` format. Actual OLT SSH settings, credentials and console
transcripts are NOT part of this public snapshot. A historic vendor
manual example does not prove this physical device's SSH settings.

R9.22 protected source snapshot SHA `7d81c6b5f1486fe39bd4c5fe338906d688634a45` adds an EXACT
per-device ZTE C320 legacy SSH transport profile from actual owner-VPS
NO-CREDENTIAL network negotiation: ssh-rsa + aes128-cbc +
diffie-hellman-group14-sha256 reached the remote authentication
stage. No real OLT credentials, device passwords, trusted console
RSA public keys, hardware CLI, management addresses or operational
secrets are included. Synthetic public CI is not proof of physical
adoption or actual account authorization. Original operational repo
remains private.

R9.23 protected source SHA `3c8aa17` adds only a NONEXECUTABLE,
firmware-conditional site SSH configuration review based on strictly
PRIVATE, owner-supplied console status, with four SYNTHETIC test cases.
No actual live OLT config, client password, real chassis RSA, direct
management addresses or serial firmware data are included or claimed.

R9.24 protected source SHA `947955b` incorporates actual strictly
credential-free server SSH test-user method discovery as nonsecret
readiness metadata (`password` offered for that username in that
session). It does NOT contain/forward any password, RSA console key,
real operator credentials or physical device CLI results. Offline
classification tests never dispatch physical OLT commands; real
adoption remains blocked on external physical source evidence.

R9.25 protected source mapping `bd733d8` corrects strictly OFFLINE
legacy SSHv2 sample diagnostic logic: vendor `not initialized` and
`disable` are ambiguous, never automatically trigger live C320 RSA
server key generation, and actual transport results still do not
constitute a real authenticated hardware read or adoption.

R9.26 protected source mapping aa308c0: strictly LOCAL synthetic
fixture regression for real site evidence gap checker. The owner's
actual site packet contains no real console RSA, firmware captures,
privileged device credentials or production operator proof. Only
sanitized source and synthetic RSA fixtures are published; all
physical adoption, real OLT login and real firmware capability
remain unverified by public CI.

R9.28 protected original source maps to draft PR128: synthetic
simulation of an ACTUALLY owner-approved physical C320 private TCP323
PASSIVE noauth response and static privately tested Rust metadata.
The live private IP is replaced with a non-operational SYNTHETIC
10.77.* fixture; original private source history, physical site
credentials/console public RSA and raw Telnet bytes are excluded.
A successful public CI never proves a real Telnet login or hardware
adoption. NO plaintext passwords were transmitted by the actual probe.

R9.30 private source `mr-ipat/ipat` PR #129 contains ACTUAL
owner-authorized interactive lab SSH+Telnet proof and no-secret
owner-private 0600 manually transcribed captures held OUTSIDE Git.
This PUBLIC mirror contains only SYNTHETIC redacted vendor-shaped
first-read fixtures and code. It removes real management IPs and
network-observed RSA fingerprints and excludes operational documents.
Public synthetic CI does NOT prove physical ZTE hardware identity,
actual permissions, production tenant authorization, full firmware
mapping, actual OLT service health, or production adoption. Hardware
passwords and first real CLI captures were NEVER exported here.

R9.31 original protected PR #130: ONLY strict OFFLINE code and entirely
SYNTHETIC private-backup fixture tests included. The owner's REAL
OLT running configuration, original protected 0700/0600 capture,
actual local file receipt, new sensitive R9.31 operational docs,
privileged session logs and vendor/customer metadata are EXCLUDED.
Actual physical backup and standalone restore claims cannot be
inferred from this public CI. Do NOT upload actual device backups.

R9.33 protected real owner-Mac verified encrypted off-VPS C320
backup and real sanitized historical board layout are ONLY presented
as static, synthetic-shaped code fixtures in PUBLIC mirror.
PRIVATE actual Restic snapshot ID, full config and credential,
raw CLI, owner-specific documents, actual device IP/network RSA
fingerprints are NOT published. Public CI exercises safety policy
and parser logic, NEVER real C320 owner credentials or remote actions.
A passing public CI does not constitute vendor-native recoverability,
production tenant authorization or automatic physical adoption.

R9.34 protected PRIVATE PR #133 actually executed ONE ephemeral
owner-approved restricted-session TEST-LAB read of physical C320,
but real owner password, actual response CLI bytes, private normalized
3-slot evidence, actual one-shot audit receipt, original management
IPv4 and network-observed RSA remain STRICTLY PRIVATE and EXCLUDED.
This PUBLIC mirror contains only REDACTED code and SYNTHETIC vendor-
shaped fixtures and denied-control tests. It NEVER performs live
privileged SSH, connects to a real device, creates a production
service account or qualifies automated SaaS adoption. Public CI is
independent software evidence ONLY, NOT a hardware certification.
