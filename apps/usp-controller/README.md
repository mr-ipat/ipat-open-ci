# Native Rust USP Controller — offline synthetic boot boundary

The first real Rust binary is `src/main.rs`, but **this is NOT a TR-369/USP wire-protocol controller**. It only offers an explicit opt-in loopback `127.0.0.1:3100/healthz` synthetic health endpoint; every other request including spoofed agent/tenant headers receives `503`. It refuses to run without `IPAT_RUN_OFFLINE_USP_LAB=1`.

`crates/usp-core` implements **non-networked, synthetic** tenant and agent enrollment/reply correlation with twelve negative/positive tests. Both `VerifiedAgent` and `TrustedOperator` are sealed against public construction. There is **no real USP protobuf schema, Record/Msg, MQTT/broker/MTP, actual certificate validation, durable session store, actual `Device.` parameter RPC or physical agent interoperability**. Never expose even this health-only binary to a public interface.

Reproduce safety tests from unprivileged Ubuntu: `cargo test --workspace --locked --offline`. Do not start the process on the live VPS until the network and out-of-band recovery gates are complete. See [R5.0 test evidence and unresolved ADR-007 scope](../../docs/USP_SYNTHETIC_R50.md).
