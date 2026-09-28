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
