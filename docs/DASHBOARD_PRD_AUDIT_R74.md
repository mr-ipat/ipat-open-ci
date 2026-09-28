# R7.4 — Audit tiga dashboard terhadap PRD v0.1

**27 September 2026 · Bukti:** SOURCE dan pengujian CI laboratorium, **BUKAN** klaim fungsi produksi. PRD tidak diubah dalam milestone ini. Semua workspace adalah selector presentasi pada SSH-loopback-only.

## PERINGATAN MERAH — DASHBOARD PRD BELUM TERPENUHI

Ketiga UI masih menggunakan fixtures. Tidak ada login OIDC/MFA pengguna ISP, verified tenant/POP session, server-driven entitlements, customer custom-domain ownership maupun inventory/ACS fisik pada UI. Ketiga business API nyata tetap HTTP 401 saat header identitas atau host dipalsukan.

| PRD | Platform Admin | Tenant Admin | Operasional NOC | Bukti / gap |
|---|---|---|---|---|
| FR-001/003 | Pemisahan metadata platform | Pembatasan tenant, POP dan menu | Sumber daya POP yang sah | Policy sintetis PASS, runtime belum |
| FR-002 | OIDC/MFA pemilik platform | OIDC/MFA + membership | Identitas & POP operator | JWT signature lab saja; login belum |
| FR-004 | Registrasi domain | Domain perusahaan, cookie terpisah | Tenant sah di domain terverifikasi | Belum |
| FR-005/008 | Tenant, paket, kuota | Tidak boleh mengelola platform | Tidak boleh billing | UI rancangan, backend belum |
| FR-006/007 | Audit dan approval hak tinggi | Audit dan delegasi | Maker-checker dan safe jobs | Source/fixture saja |
| FR-009/010/013 | — | Inventory tenant | ACS/USP perangkat nyata | Interop fisik belum |
| FR-016/017 | — | Hanya OLT milik tenant | Satu C320 baca-saja per firmware | Parser offline, TC-OLT-01 NOT RUN |
| FR-020/023/024/029 | — | Subscriber dan topologi | PPPoE, diagnosis, telemetri | Operasional belum aktif |

**R74 UI update:** kotak merah GAP_LEDGER menunjukkan tiga gap menurut workspace. Ledger ini static audit, BUKAN hasil realtime atau pengendalian privilege. Semua demonstrasi tetap privat dan semua API bisnis nyata tetap menolak tanpa sesi sah.

## Keputusan persyaratan

**Ikuti PRD v0.1.** Simulator S1 pada FR-016 diperbolehkan bila hardware belum tersedia. Pernyataan pemilik bahwa perangkat pengujian tidak live dicatat sebagai deklarasi laboratorium; belum menjadi bukti identitas, versi, atau kompatibilitas perangkat. Jangan menurunkan security gate untuk mengejar tampilan produk.

MUST tahap dashboard lab terautentikasi: OIDC Authorization Code + PKCE & MFA, issuer/audience terpin; membership/POP operator-approved dari database tepercaya; server-driven menu; API/jobs authz deny-default; RLS negatif lintas tenant/pool; audit/redaction, dan account separation antara platform owner dan secret tenant.

SHOULD: agregasi data perangkat/diagnostik lebih luas sesudah sumber data valid. LATER: transaksi billing, advanced SSO, dan kampanye firmware massal dengan persetujuan tersendiri. Arsitektur ADR-005/006/009/014 tetap sesuai status dalam register; tidak ada persetujuan baru diam-diam.

Rujukan: PRD.md, DASHBOARDS_R68.md, DASHBOARD_MEMBERSHIP_R70.md, PRD_DEVIATIONS_R71.md, SECURITY.md dan PROJECT_STATUS.md.


## R7.5 sequencing clarification

The owner has approved delaying FR-004 verified subdomain/custom-domain
and across-domain cookie/session work to M2 after private lab integration
(ADR-020). Platform Admin FR-004 is a planned later dependency,
not a completed feature or blocker to private simulator/read-only lab.
FR-001/002/003 authorized data/POP isolation and credible customer
login/backend/menu are NOT deferred. The three dashboards remain
synthetic previews and retain red PRD gaps.


## R7.6 exact Fadly hostname intent (unverified)

The owner-provided company illustration is future Fadly custom
domain hub.example.invalid (also CURRENT VPS SSH management target), with
ipat.id reserved as intended future platform branding. Neither is
an active tenant dashboard. Existing single operator SSH-loopback
preview remains synthetic with all three business namespaces HTTP401.
Issuer+subject-to-candidate-row Rust policy tests are a foundation
only: still NO actual OIDC/MFA/company membership or server-side
menu/data-plane integration. Custom domains remain deferred; data
isolation MUST NOT be deferred. See DOMAIN_INTENT_FADLY_R76.md.
