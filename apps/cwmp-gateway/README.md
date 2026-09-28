# CWMP gateway — original Rust implementation boundary

The first offline security-oriented parser is in `crates/cwmp-protocol`. It accepts a deliberately restricted SOAP 1.1 / CWMP 1.0 synthetic Inform document with explicit XML/node/depth limits and DTD rejection, then produces pure InformResponse XML. This is a **parser/serializer**, not a networked ACS engine.

**Not implemented:** HTTPS/CPE authentication, tenant-device binding, anti-replay, sessions, production SOAP faults, version negotiation, outbound parameter RPCs, and real ONT interoperability. Do not expose this module as a public CPE listener until transport identity and tenant authorization tests pass.

See `docs/PRD.md` AC-03 and `docs/DEVICE_MATRIX.md`. No device/model/firmware support is established by simulator fixtures.


## R4.9 offline simulator milestone

[CWMP offline admission test evidence and limitations](../../docs/CWMP_ADMISSION_R49.md). The new pure `cwmp-admission` Rust crate enforces synthetic per-device enrollment tied to tenant ID and pinned simulated client-SPKI identity, bounded active sessions/replay tracking and response only after admission. Its `AuthenticatedPeer` is **sealed against public construction** until a properly reviewed real mTLS transport adapter exists. This is **NOT** an HTTP/HTTPS gateway, a durable CWMP session, a `GetParameterValues` RPC or tested physical ONT support. No internet listener is authorized. The gateway executable was NOT IMPLEMENTED as of historical R4.9; R6.6 now adds an explicitly local, unauthenticated-parser-only executable while actual authenticated CPE ingress remains blocked.

## R6.6 original Rust opt-in loopback parser and one-read domain state

The new Rust executable in `src/main.rs` runs ONLY with `IPAT_RUN_OFFLINE_CWMP_LAB=1` and binds 127.0.0.1:3300. `POST /lab/parse-inform` validates bounded untrusted synthetic XML and returns generic parser status without serial/tenant/peer authentication. **The actual `/cwmp` route unconditionally denies with HTTP 503**, including if untrusted HTTP headers claim a valid client certificate or tenant. It issues no InformResponse and never accepts real CPE enrollments.

Separately, `crates/cwmp-protocol/src/rpc.rs` implements only allowlisted `GetParameterValues` request/strict response and sanitized CWMP fault parsing; `crates/cwmp-admission/src/read.rs` requires the existing sealed synthetic trusted peer/lease and exact empty CPE POST to advance a one-read session. All runtime authentication, real HTTPS/mTLS, durable per-tenant sessions and CPE support remain unimplemented. See [R6.6 executable and synthetic protocol tests](../../docs/ACS_CWMP_R66.md).

## R6.7 autentikasi kriptografis TLS 1.3, hanya laboratorium

`src/bin/cwmp-mtls-lab.rs` menjalankan **proses Rust terpisah** pada literal `127.0.0.1:3433`, memerlukan opt-in eksplisit, bukan root, CA klien dan pasangan sertifikat/key server dari folder lokal pribadi mode 0700, file mode 0600. Rustls `WebPkiClientVerifier` memaksa clientAuth berantai CA yang benar, tanpa mode anonim atau TLS trust bypass. Skrip sementara membuktikan TLS1.3 asli: klien dipercaya berhasil, tanpa sertifikat/CA salah/EKU salah gagal, DNS/CA server salah ditolak. Server hanya menyediakan parser laboratorium mTLS dan **tetap mengembalikan `/cwmp` 503** untuk semua klien, termasuk dengan sertifikat yang lolos TLS. Verifikasi sertifikat CA tidak menentukan tenant maupun pemilik perangkat; belum ada mTLS-to-sealed-`cwmp-admission` trust adapter. [Dokumentasi dan gap R6.7](../../docs/ACS_MTLS_R67.md).
