# IPAT R5.2 — synthetic evidence-led diagnostic engine

**Scope:** Rust `crates/diagnostic-core` only. No device connection, persistent incident, alarm/action side effects, network listener, production inference model or measured field accuracy. Exact real hardware/firmware must still be inventoried and verified.

This implements a deterministic **synthetic baseline** for PRD FR-024 and provisional AC-06: independent distribution uplink event combined with **two distinct** same-tenant/same-path subscriber reachability-loss observations and caller-verified topology → distribution-path *hypothesis*; a single ONT LOS plus recent healthy uplink and neighboring ONT → ONT/PON access *hypothesis*; PPPoE authentication rejection plus independent normal optical evidence and healthy uplink for the **same subscriber** → PPPoE *hypothesis*. Missing CWMP Inform alone is ALWAYS insufficient; never infer a cut fiber or automatically restart/write subscriber devices.

Each normalized event includes canonical `TenantId`, POP, distribution path, optional subscriber, signal, source identifier and observed-at timestamp. An explicit tenant/POP/path mismatch rejects the entire batch without cross-tenant correlation. The caller-provided `topology_verified` flag is **not authenticated by this crate** and must come from a future trusted topology DB+authz layer, never a client header. Stale events are excluded according to bounded freshness policy and counted; events timestamped in the future, malformed source/scope labels and oversized batches fail closed. Contradictory uplink or optical observations produce `ConflictingEvidence`, requiring operator review instead of arbitrary deterministic prioritization. Returned evidence retains source and timestamp; inferred impact is limited to the observed synthetic subscriber identifiers, not a promise of complete real topology. All outcomes set `remediation_permitted=false` and require human review.

## Tests and run steps

```bash
# From reviewed IPAT repository on Ubuntu 26.04:
cargo fmt --all -- --check
cargo test -p diagnostic-core --locked
cargo test --workspace --locked
```

Ten deterministic Rust unit tests cover three differentiable synthetic scenarios, CWMP missing-only, missing verified topology, stale evidence, cross-tenant/POP rejection, contradictory signals, invalid/future/oversized inputs and duplicate subscribers not falsely satisfying the distribution impact threshold. Tests are pure offline simulations. Reference: [PRD.md](PRD.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [PROJECT_STATUS.md](PROJECT_STATUS.md).

**Not implemented:** real topology authority, authentic signal adapters and event normalization, subscriber data persistence, time sync proof, confidence calibration/false-positive measurement, SLO, downstream real impact determination, dashboard, approval pipeline and automated root-cause remediation (intentionally prohibited until safety controls). Do not label any real OLT/ONT/MikroTik combination verified from these fixtures. No Linux firewall, cluster, PostgreSQL server, SSH or external network configuration changes are made by this milestone.


## Actual verified post-merge execution

PR [#35](https://github.com/mr-ipat/ipat/pull/35) merged as `0fa05a9d3a637019287fc3737b2927a2eae53395`; final GitHub main [workflow 36143747994](https://github.com/mr-ipat/ipat/actions/runs/36143747994) **SUCCESS**. The exact GitHub/Mac/actual Ubuntu 26.04.1 source SHA matched; the real Ubuntu `cargo fmt --all -- --check` and workspace **68/68 Rust tests passed**, with 34 existing lab Python and five PostgreSQL static checks. Its latest encrypted Mac source snapshot `706129c3`, historic readable config, and separately the real root-selected config snapshot `abaa9827` were independently checksum/content-restored; full `restic check --read-data` **19 snapshots/36 packs**, no errors. These are pure simulated incident tests: **no field evidence, calibrated accuracy or live customer-facing diagnosis is claimed**.
