# R7.3 — ZTE C320 offline card/version correlation (NOT device interoperability)

**Date:** 2026-09-26 · **Target:** FR-016 initial offline parser; TC-OLT-01 remains NOT RUN.

## Why this small fix matters

Some historical ZTE C320 command-reference examples display different `CfgType`
and `RealType` for one slot, while `show version-running` reports the configured
type for that same slot's `MVR`. The earlier offline IPAT importer compared only
`RealType`, so it incorrectly rejected this otherwise structurally consistent
synthetic pair. A prior manual is NOT proof of current hardware compatibility.

## Scope and restrictions

- `olt-core::Card` records both `configured_type` and physical `card_type`.
- `consistent_inventory` demands one `MVR` row per card at the EXACT slot.
- A version card type must equal either the configured or physical type from
  that observed slot. Unrelated types, a different slot, and boot-only records
  remain rejected. No inferred aliases by prefix or vendor family.
- The existing private offline importer calls this shared cross-check.
- Python/Rust tests use **synthetic** vendor-manual-shaped rows; no packets,
  real serial numbers, OLT CLI access, firmware image or network write.

## Verification

Run `cargo fmt --all -- --check` and
`cargo test --locked -p olt-core --test c320_fixture`.
Then build the reviewed importer and run its Python contract:
`cargo build --locked -p olt-core --bin c320-offline-review` and
`python3 -m unittest discover deploy/scripts/lab/r71 -p test_r71_offline_cli.py -v`.
Record actual CI/host evidence in PROJECT_STATUS before claiming these pass.

## Red open PRD gap

**NO REAL ZTE C320 IS CONNECTED.** This is offline format compatibility only.
DEV-01 board list and running firmware remain unobserved. No confirmed private
trusted management route, independent host-key proof or read-only account is
available in this milestone; FR-017 firmware writes remain disabled. Firmware
update additionally requires official exact-release proof, approved window,
independent recovery, maker-checker and onsite rollback. See
`PRD_DEVIATIONS_R71.md`, physical issue #72 and firmware issue #73.
