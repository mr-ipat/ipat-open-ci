# IPAT — Product Requirements Document (PRD) v0.1

| Metadata | Nilai |
|---|---|
| Produk | IPAT (`IP@`) — Integrated Provisioning, Automation & Telemetry |
| Versi/tanggal | v0.1 / 2026-09-25 (Asia/Jakarta) |
| Status | **Baseline persyaratan untuk implementasi; validasi dan persetujuan akhir product owner masih diperlukan** |
| Cakupan | Platform SaaS multi-tenant untuk provisioning, manajemen, telemetri, diagnostik, dan otomasi ISP |
| Sumber primer | `IPAT_PROJECT_BRIEF.md`, approved design baseline; project instructions |
| Dokumen pendamping | `ARCHITECTURE.md`, `SECURITY.md`, `DEVICE_MATRIX.md`, `DECISIONS.md`, `SPRINT_BACKLOG.md`, `DEPLOYMENT.md`, `PROJECT_STATUS.md` |
| Kaidah | `MUST` = persyaratan wajib; `SHOULD` = disarankan; `LATER` = di luar fase awal. Status desain bukan bukti implementasi. |

> **Aturan perubahan:** Brief menetapkan keputusan mengikat. Dokumen ini merinci dan mengusulkan pilihan yang belum final; keputusan usulan bertanda **PROPOSED** dan harus disetujui melalui `DECISIONS.md`. Tidak ada klaim kompatibilitas, uji, keamanan, SLA, atau performa tanpa bukti. Dokumen ini adalah acuan pekerjaan v0.1, bukan pengesahan kesiapan produksi.

## 1. Ringkasan dan tujuan

IPAT menyatukan manajemen CPE melalui ACS TR-069/CWMP asli dalam Rust dan Controller native TR-369/USP, pengelolaan OLT/ONT serta MikroTik, topologi/subscriber, diagnostik berbasis bukti, otomasi terkontrol, observability, dan isolasi SaaS per perusahaan. Positioning membedakan *cakupan fungsi* IPAT dari ACS konvensional, bukan mengklaim kompatibilitas atau performa yang belum dibandingkan secara empiris.

**Outcome pengguna:** NOC melihat subscriber dan dependensi jaringan dalam satu konteks; provisioning officer menjalankan perubahan massal yang dapat ditinjau/diulang aman; security admin memeriksa dan menyetujui aksi berisiko; platform owner mengelola langganan dan tenant tanpa otomatis melihat kredensial tenant.

**Outcome MVP tujuh hari:** potongan alur terintegrasi yang berjalan di laboratorium, bukti tes positif dan negatif, serta fondasi yang dapat dikembangkan. Jika perangkat nyata/node kedua tidak tersedia, demonstrasi simulator dibedakan tegas dari kelulusan tes fisik.

**Indikator yang akan diukur (bukan janji):** jumlah kombinasi firmware tervalidasi per fitur; kelulusan tes isolasi dan deny-by-default; success/failure CWMP Inform/RPC dan USP PoC; perubahan PPPoE tanpa efek ganda; ketepatan/keterlacakan hipotesis diagnostik; throughput queue, error rate, p95 latensi, pemakaian node, RPO/RTO hasil tes.

## 2. Pengguna, tata kelola, dan alur utama

- **Platform owner admin:** provisioning tenant, domain tervalidasi, paket/kuota, pemakaian agregat; tidak otomatis mengakses data operasional/secret tenant.
- **Tenant admin:** pengguna, organisasi, POP/region dan policy tenant sesuai delegasi; bukan hak universal lintas tenant.
- **System admin / security admin:** masing-masing operasi sistem dan policy/approval/audit; *separation of duties* untuk operasi berisiko.
- **NOC manager / engineer:** pemantauan, triase, perubahan teknis yang diizinkan sesuai POP.
- **Provisioning officer:** onboarding perangkat dan job terbatas, dry-run; aksi massal perlu approval.
- **Helpdesk / field technician:** hanya subscriber/diagnostik dan tugas lapangan sesuai scope; tidak melihat menu atau data di luar hak.
- **Auditor:** pembacaan audit yang diizinkan tanpa mengubah perangkat; **service identities** terpisah dari manusia.

Alur utama J-01: platform owner membuat tenant → domain subdomain/custom diverifikasi → tenant admin diundang → login MFA dan policy → hanya dashboard/aksi milik tenant terlihat. J-02: perangkat didaftarkan dengan ikatan identitas tenant → Inform/USP message atau polling diverifikasi → inventory/subscriber/topologi diperbarui → NOC melihat data berlabel freshness. J-03: batch PPPoE CSV → validasi → preview/diff/dry-run → approval terpisah → worker ber-rate-limit → rekonsiliasi, bukti dan audit. J-04: alarm uplink → korelasi bukti topologi dan pelanggan → hipotesis berperingkat internal dengan ketidakpastian, bukan vonis tunggal → operator menentukan tindakan.

## 3. Keputusan tetap, usulan, dan non-goals

### 3.1 Wajib dipertahankan (APPROVED baseline)

1. Backend Rust/Tokio/Axum pada Ubuntu Server 26.04 LTS; **ACS CWMP/TR-069 original Rust, bukan GenieACS**. Referensi interoperabilitas implementasi lain tunduk pada lisensi.
2. Modul **native USP Controller TR-369** sejak hari pertama dengan abstraksi perangkat bersama; jangan menyebut dukungan lengkap sebelum uji. MQTT = kandidat MTP awal, belum keputusan final.
3. Modular monolith sebagai domain bisnis dengan pemisahan proses protocol endpoints/worker/infrastruktur sewajarnya; tidak memecah banyak microservice prematur.
4. K3s lintas VPS/bare-metal heterogen, queue, worker concurrency terbatas, backpressure, locking per perangkat, idempotensi; penambahan node tidak boleh menduplikasi job.
5. PostgreSQL dengan rencana primary/standby, PITR dan backup terpisah untuk produksi; HA tidak diklaim oleh node lab tunggal.
6. Isolasi multi-tenant menyeluruh; dashboard dan domain tiap perusahaan, antarmuka platform terpisah; RBAC+ABAC deny-by-default, MFA, approval + audit aksi tinggi; menu terlarang tersembunyi **dan** backend menolak semua jalur akses.
7. Diagnostik *evidence-led* yang membedakan domain gangguan dan menyatakan freshness/ketidakpastian; tidak menganggap ketiadaan Inform membuktikan fiber putus.
8. IaC: Ansible, K3s bootstrap/join, Helm+GitOps, Terraform bila penyedia VPS mendukung; secret di luar Git.

### 3.2 Keputusan kandidat (PROPOSED; lihat ADR)

- Frontend Next.js/TypeScript; identity Keycloak OIDC/MFA; RabbitMQ sebagai **work queue**; Prometheus/Grafana; secret manager yang dipilih kemudian.
- Pola penyimpanan awal: **platform metadata terpisah secara logis**, tabel operasional berbagi PostgreSQL dengan `tenant_id`, Row-Level Security (RLS), `FORCE ROW LEVEL SECURITY`, role runtime tanpa `BYPASSRLS`; kemungkinan migrasi dedicated database untuk tenant besar setelah evaluasi. Pola ini bukan substitusi otorisasi aplikasi atau isolasi backup.
- USP MTP awal MQTT dengan broker/otorisasi terpisah dari antrian job, pilihan broker belum disahkan.
- RPO/RTO produksi, retensi telemetri, kuota paket, profil autoscaling dan target kapasitas belum disahkan.

### 3.3 Eksplisit di luar jaminan tujuh hari

Tidak termasuk: seluruh RPC/TR-069 dan USP secara lengkap; sertifikasi perangkat; semua vendor/firmware; bulk firmware upgrade; remedi otomatis skala besar; billing/transaksi keuangan; HA/failover produksi; 100% akurasi RCA; autoscaling di semua penyedia cloud; bukti performa/keamanan lebih unggul dari produk lain.

## 4. Prioritas dan batas fase

| Area | MUST — target demonstrasi 7 hari (jika dependensi tersedia) | MUST — sebelum rilis komersial | SHOULD | LATER |
|---|---|---|---|---|
| Identity/tenant | Dua tenant sintetis, OIDC/MFA dev, entitlements UI/API, tes negatif | End-to-end lintas data-plane, domain verified, secret boundaries, approval | Delegasi POP/region rinci | Advanced SSO per enterprise |
| ACS | Rust endpoint HTTPS, Inform valid, session/fault dasar, 1 RPC parameter yang diuji | Metode prioritas lengkap menurut matriks, hardening/load/interoperabilitas | Templates/device profiles | Firmware campaign skala luas |
| USP | Boundary, protobuf, simulator-agent PoC dengan satu flow; jika MTP tak siap tandai design-only | Native Controller interoperabel dan aman, MTP terpilih, reconnect/retry | Transport alternatif | USP Service orchestration luas |
| OLT/ONT | Inventory/read-only via simulator dan perangkat bila ada | Adapter per kombinasi **teruji**, approval write | Event normalization multivendor | Ekspansi vendor |
| MikroTik | Read secret/session lab, CSV dry-run, batch kecil idempotent ber-approval | Rate-limit/rollback strategy/partial-failure handling | Template provisioning kompleks | Autonomous mass changes |
| Topologi/diagnostik | Hubungan dasar dan 3 rule simulated incident | Evidence store, stale-data guard, dampak, alarm pipeline | Korelasi lebih kaya | ML RCA setelah dataset |
| Operasi/scale | Local compose, deploy single-node, worker + outbox/lease PoC, backup-restore | K3s heterogen, node lifecycle, benchmark, HA DB, DR tervalidasi | Autoscaling dinamis | Multi-region active-active |

Catatan: **MUST produk** tidak sama dengan *selesai hari ketujuh*; kegagalan dependensi lab tidak boleh diganti klaim tes fisik. Tentukan prioritas cut-line di `SPRINT_BACKLOG.md`.

## 5. Persyaratan fungsional (FR)

Semua FR memiliki `tenant_id`/otorisasi yang sesuai atau eksplisit `platform-scope`; ID digunakan untuk melacak implementasi dan tes. `S1` = potongan 7 hari, `C` = sebelum komersial, `S` = SHOULD sesudah S1; label S1 mengasumsikan dependensi perangkat bila relevan.

### 5.1 Tenant, identitas, otorisasi

| ID | Prioritas | Persyaratan & kondisi penerimaan |
|---|---|---|
| FR-001 | S1 | Buat minimal dua tenant sintetis yang terisolasi; query/command yang salah tenant ditolak di UI, API, service, job, search dan export. |
| FR-002 | S1→C | Login OIDC dengan MFA untuk privileged users dan sesi tenant-scoped; user tenant lain tidak dapat memalsukan context via header/host/token. |
| FR-003 | S1 | Policy RBAC + ABAC deny-by-default: action/resource/tenant/POP; menu tak berhak tidak dirender, API memberikan 403/404 sesuai kebijakan tanpa bocor metadata. |
| FR-004 | C | Verifikasi kepemilikan subdomain/custom domain, TLS per domain, isolasi cookie/session/branding tenant, mapping domain↔tenant tervalidasi. |
| FR-005 | S1→C | Antarmuka platform owner terpisah, tidak ada akses otomatis terhadap credential/data operasional tenant. |
| FR-006 | S1→C | Audit siapa/kapan/aksi/tenant/resource/hasil/correlation-id tanpa secret; log akses lintas tenant ditolak juga dicatat. |
| FR-007 | S1→C | Aksi berisiko memiliki klasifikasi, dry-run, approval *two-person* bila ditetapkan, expiry, reason, dan opsi emergency tercatat. |
| FR-008 | C | Pengelolaan plan/kuota/pemakaian tenant; hard quota enforced server-side, tanpa billing transaksi sebelum scope eksplisit. |

### 5.2 Protocol endpoint dan management abstraction

| ID | Prioritas | Persyaratan & kondisi penerimaan |
|---|---|---|
| FR-009 | S1 | ACS native Rust menerima HTTPS CWMP Inform dengan parsing SOAP/XML aman, autentikasi & binding tenant-per-device tervalidasi, mengirim InformResponse. |
| FR-010 | S1 | Menyimpan lifecycle/session, event/identity CPE, correlation ID; satu parameter discovery/get yang benar-benar dibuktikan pada simulator/ONT; hasil beda per model ditulis di matriks. |
| FR-011 | C | Workflow parameter discovery/read/write, RPC lifecycle/fault/timeout/retry dengan state dan per-device serialization; perintah write hanya pada profil teruji/diizinkan. |
| FR-012 | C | Secure connection-request handling sesuai kemampuan CPE; anti-replay, credential handling, rate limiting, ukuran dan batas XML; kebijakan fallback tanpa downgrade diam-diam. |
| FR-013 | S1 | Native USP Controller boundary terpisah, protobuf schema dan pemetaan `agent_endpoint_id` terverifikasi; satu interaksi PoC dengan simulator atau agen kompatibel, status bukti eksplisit. |
| FR-014 | C | Implementasi USP MTP, autentikasi/otorisasi controller-agent, korelasi/duplicate/reconnect, method prioritas dan interoperability suite. |
| FR-015 | S1→C | Normalized device model mengikat tenant/device/protocol/observations, menjaga raw capability/vendor extensions terpisah dan menyatakan sumber data. |

### 5.3 Adapter OLT/ONT/MikroTik dan provisioning

| ID | Prioritas | Persyaratan & kondisi penerimaan |
|---|---|---|
| FR-016 | S1 | Inventory awal ZTE C320 dan C-DATA OLT sebagai **target uji**; discovery/read-only melalui kanal yang benar-benar tersedia, jika tidak simulator. |
| FR-017 | C | Adapter berdasarkan `(vendor, exact_model, firmware, protocol, feature)`; write disembunyikan/ditolak bila kombinasi tidak tervalidasi. |
| FR-018 | S1→C | ONT VSOL/ZTE teridentifikasi dengan exact model, hardware revision, firmware, serial/identifier, CWMP data model/capability; status per fitur. |
| FR-019 | S1 | MikroTik x86/CCR/RB distribusi dan RB pelanggan sebagai target fisik; baca PPPoE secret/session di router lab via secure API/REST yang tersedia. |
| FR-020 | S1→C | Bulk PPPoE CSV tervalidasi schema/duplikasi/tenant/policy, preview diff/dry-run; approval sebelum apply, rate-limit per router, idempotency key; report per item. |
| FR-021 | C | Aman saat timeout dan partial success: reconcile actual state sebelum retry; unknown outcome menahan tindakan potensial ganda dan mengeskalasi manual. |
| FR-022 | C | Network credentials per tenant tersimpan via secret manager, terenkripsi in transit dan audit akses; tidak tampil di export/log/helpdesk. |

### 5.4 Subscriber 360, topologi, insiden

| ID | Prioritas | Persyaratan & kondisi penerimaan |
|---|---|---|
| FR-023 | S1 | Model subscriber ↔ PPPoE ↔ CPE ↔ ONT ↔ OLT/PON ↔ distribusi; hubungan boleh `unknown` dan memakai provenance/freshness. |
| FR-024 | S1 | Incident simulator minimal: uplink distribusi memengaruhi >1 subscriber, ONT tunggal, dan PPPoE tunggal; hipotesis/evidence berbeda. |
| FR-025 | C | Correlation engine menunjukkan hipotesis domain, bukti pro/kontra, timestamp, confidence yang terkalibrasi (jika metrik tersedia), caveat dan affected subscribers. |
| FR-026 | C | Alert dedup, acknowledgement, timeline, severity dan audit; tidak ada auto-remediation high impact tanpa policy/test/approval. |
| FR-027 | S | Menampilkan kualitas data stale/missing/conflicting, observasi dari banyak protocol dan sumber per perangkat. |

### 5.5 Platform operations, orkestrasi dan audit

| ID | Prioritas | Persyaratan & kondisi penerimaan |
|---|---|---|
| FR-028 | S1 | Job store dan queue outbox transaksional, pengambilan job ber-lease, retry terbatas, dead-letter/failed terminal, idempotency dan per-device mutual exclusion. |
| FR-029 | S1→C | Dashboard operator dan metrik auth/protocol/job/db/diagnostics, structured logs, tracing ID; metrics labels tidak mengungkap tenant rahasia. |
| FR-030 | S1 | Backup PostgreSQL lab dan bukti restore ke instance isolasi; hasil checksum/konsistensi dicatat. |
| FR-031 | C | HA DB primary+standby dengan failover teruji, PITR dan backup offsite terpisah; DR runbook dengan RPO/RTO hasil ukur. |
| FR-032 | S1→C | IaC/node lifecycle: bootstrap Ubuntu, K3s join, validasi allocatable/resources, drain/remove dan restore; node kedua diuji bila tersedia. |
| FR-033 | C | Pengukuran kapasitas heterogen berdasar utilisasi riil, queue age, Inform throughput, USP sessions, latency dan error; resource scheduling disetel dari bukti. |
| FR-034 | C | Lifecycle data retention dan deletion per tenant, ekspor aman, recoverability dan prosedur offboarding termasuk backup-retention implications. |
| FR-035 | C | Notifikasi/search/export/webhook jika diaktifkan menegakkan policy yang sama termasuk sink yang menerima data. |
| FR-036 | SHOULD (post-S1) | Optional native IPAT host-firewall policy planner (Ubuntu nftables adapter later) with dry-run, explicit dual-stack source CIDRs, protected K3s private-only ports, RBAC+ABAC/maker-checker, immutable diff, audited TTL rollback and independent console/recovery gate. No external hosting-provider firewall API dependency. Pure planner does not count as live firewall or validated nftables deployment. |

## 6. Persyaratan nonfungsional (NFR) dan cara membuktikan

| ID | Kebutuhan | Lab 7 hari | Kriteria sebelum komersial (target **PROPOSED**, belum SLA) |
|---|---|---|---|
| NFR-01 | Isolasi | Semua jalur yang diimplementasikan memiliki tes silang tenant/POP negatif | Threat-model lengkap, tenant escape tests lintas API/queue/storage/restore/domain, hasil 0 kebocoran pada rangkaian tes disepakati |
| NFR-02 | Auth/security | MFA privileged login dev; TLS test; secret dummy | Pentest independen, key rotation, signed images/SBOM, privilege audit, incident playbook |
| NFR-03 | Reliability | Satu node dan restore lab; tidak mengaku HA | SLO layanan, error budget, HA/failover/chaos/DR melalui tes berkala |
| NFR-04 | Performance | Rekam p50/p95/p99 Inform/RPC/job/API, baseline hardware + load shape | Tetapkan latency SLO dan kapasitas terukur per profil tenant/device dengan kriteria persentil |
| NFR-05 | Scaling | Bukti queue ownership dan tidak ada duplicate application yang teramati pada test | Multi-node heterogen, fault/retry tests, capacity plan berdasarkan bottleneck stateful/IO/network |
| NFR-06 | Durability | Backup restore + checksum sample | PostgreSQL PITR, offsite/immutable backup, failover, restore dan RPO/RTO terukur |
| NFR-07 | Observability | Structured logs, metrics, correlation-id | Traces & redaction, audit retention/immutability, alert routing; tenant label cardinality terkendali |
| NFR-08 | Maintainability | Rust workspace modular, migrations/tests/runbook | CI gate, backward-compatible schema/APIs, semver adapters, upgrade/rollback drills |
| NFR-09 | Portability | Ubuntu 26.04 LTS + local compose + K3s dev | Tested VPS/bare-metal joining/draining and storage class/network restrictions documented |
| NFR-10 | Data quality | Timestamps + source/protocol, unknown/stale states | Freshness objectives by signal, conflict resolution audit, device profile regression |

**Sizing:** node awal baseline *provisional* dari brief ialah **16 vCPU, 64 GiB RAM-class, ~1 TB NVMe** + jaringan privat dan backup eksternal. 16 vCPU/32 GiB/250 GB bukan baseline yang disepakati dalam brief dan, bila dipakai, hanya opsi dev sangat terbatas setelah anggaran/retensi/telemetri diubah dan dibuktikan oleh pengukuran. Opsi beban pilot berat 16 vCPU/128 GB/~2 TB juga provisional. Hitung ulang setelah mendapat jumlah tenant, ONT online, frekuensi Inform/polling, USP sessions, retention, jobs/hour dan persyaratan SLO.

## 7. Acceptance criteria dan bukti minimum

| ID | Gate | Skenario, oracle, dan evidence |
|---|---|---|
| AC-01 | S1 MUST | Dua tenant Kangnet/Nengnet **sintetis**: seluruh endpoint yang diimplementasikan gagal jika cross-tenant; uji UI, direct URL, API, query/search, export, queued job, termasuk manipulasi host/header/token. |
| AC-02 | S1 MUST | Helpdesk tak melihat kategori terlarang; direct API menolak; batas POP/subscriber berlaku. Bukti screenshot/menu snapshot + test 403/404 tanpa bocor. |
| AC-03 | S1 MUST | ACS Rust simulator: Inform + InformResponse valid dengan session + raw logs redacted; jika ONT lab tersedia, ulang dengan model/firmware nyata dan 1 RPC parameter sukses. Tanpa fisik, status **simulator-only**. |
| AC-04 | S1 MUST | USP modul/controller boot dan PoC satu message dengan simulator/agent beridentitas yang terverifikasi; bila belum ada kompatibilitas riil, status *PoC*, bukan supported vendor. |
| AC-05 | S1 MUST | MikroTik: tes baca PPPoE via lab/simulator, CSV invalid ditolak, dry-run tidak menulis, approval dan duplicate key mencegah job ganda; catat partial-failure scenario. |
| AC-06 | S1 MUST | 3 skenario incident menghasilkan domain hipotesis berbeda, evidence/source/age dan disclaimer unknown; satu observasi CWMP missing tak memicu vonis fiber cut. |
| AC-07 | S1 MUST | Backup PostgreSQL dan restore ke isolated instance dengan row counts/integrity sampel; hasil dicatat. |
| AC-08 | S1 CONDITIONAL | Node kedua heterogen join dan menjalankan job eligible; tes gangguan/restart worker dan tidak ada duplicate side effect dalam skenario; jika node belum ada, ditandai BLOCKED. |
| AC-09 | C | Customer custom domain tidak bisa mengambil tenant lain melalui host spoofing; TLS/session/domain ownership policy ditest. |
| AC-10 | C | ACS interop per metode/firmware berdasarkan matriks, termasuk malformed XML, timeout, auth failures; tidak menggeneralisasi model lain. |
| AC-11 | C | USP authenticated interoperability/conformance sesuai target fitur/amendment; setiap metode dan MTP punya evidence. |
| AC-12 | C | OLT ZTE/C-DATA read-only dan aksi write yang diusulkan teruji per firmware dengan rollback/outage control terpisah. |
| AC-13 | C | Production DB failover + PITR + backup offsite restore memenuhi RPO/RTO yang sudah disetujui dan diukur. |
| AC-14 | C | Pengujian multi-node/no-double-execution, queue backpressure, per-device serialization, resilience dan scale-down graceful. |
| AC-15 | C | Penetration test, access control matrix per role/POP, privilege escalation, custom domain SSRF/cross-domain, log redaction lulus gate keamanan. |
| AC-16 | C | Tenant onboarding/offboarding, data deletion/backup retention sesuai kontrak dan proses compliance yang ditetapkan. |
| AC-17 | SHOULD (post-S1) | Native firewall planner rejects unrestricted SSH/control-plane ingress for both IP families, fails closed on missing route/authorization, and records dry-run evidence. A later live host-agent acceptance requires isolated disposable-node nftables/CNI tests, complete independently recoverable backup and out-of-band access, rollback drill, signed high-risk approval, new SSH session and dual-stack ingress verification. Until then execution must be unavailable. |

**Gate akhir Sprint 1:** AC-01 s.d. AC-07 dinilai pass/fail/blocked dengan lampiran bukti; AC-08 bersyarat. *No-go* pada potongan yang merusak isolasi tenant, kontrol approval, atau melakukan write di luar scope. Klaim perangkat nyata hanya jika tes benar-benar terjadi dan `DEVICE_MATRIX.md` diperbarui.

## 8. Pengujian, laboratorium dan bukti

**Piramida:** unit Rust untuk parser/policy/rules/state machine; property/fuzz untuk SOAP/XML, parsers, CSV dan policy; integration PostgreSQL/RLS/outbox/RabbitMQ/identity; contract simulators CWMP dan USP; e2e tenant/menu/API; physical per `(model, firmware, protocol, feature)`; performance/failure/restore; security dan operasi. CI wajib melarang tes simulator diberi label tes fisik.

**Perangkat pilot:** ZTE C320 dan C-DATA OLT (model C-DATA belum diketahui); VSOL dan ZTE ONT (model/firmware belum diketahui); MikroTik distribusi x86/CCR/RB dan MikroTik RB pelanggan (model/RouterOS/version belum diketahui). VSOL GPON OLT **bukan** perangkat fisik pilot yang terkonfirmasi. Baca `DEVICE_MATRIX.md` untuk template data yang wajib dikumpulkan.

**Physical test protocol:** catat serial dengan masking untuk laporan publik, hardware revision, RouterOS/firmware build, lisensi/fitur dan jaringan lab; dapatkan izin/maintenance window, ekspor backup konfigurasi ke repositori aman, batasi VLAN/jalur dan rate, snapshot baseline, jalankan read-only dahulu, kemudian 1 perubahan kecil yang diotorisasi dan tervalidasi, amati diff, lakukan restore bila perlu. Cegah pencampuran perangkat produksi dengan simulasi. Simpan evidence run ID, version/git SHA, timestamp, sanitised request/response, hasil, limitasi dan operator.

**Matrix status:** `untested`, `partial`, `validated` hanya untuk kombinasi fitur tertentu; `blocked` dapat dicatat sebagai outcome pengujian, bukan kompatibilitas negatif umum. Jangan mengekstrapolasi lintas firmware.

## 9. Arsitektur pada tingkat produk

Frontend tenant + platform admin mengakses Axum API melalui verified domain ingress. Keycloak/OIDC (proposed) menerbitkan identity; policy engine Rust menegakkan tenant/POP/aksi; domain core modular mencakup tenant, inventory, subscriber, topologi, diagnosa, provisioning dan audit. Service ACS Rust dan USP Rust terpisah di sisi protocol, tetapi berbagi normalized device model dan domain/queue. OLT + MikroTik adapter menjalankan read-only discovery dan write terkontrol. RabbitMQ work queues (proposed), transactional PostgreSQL outbox/job store dan bounded worker menghasilkan pemrosesan yang dapat dipulihkan. PostgreSQL operational RLS + platform metadata separation, object store/backup terpisah dan secret management lintas tenant. K3s dan tools IaC mengelola compute, sedangkan database HA/backup berdiri sendiri. Lihat `ARCHITECTURE.md` untuk rancangan data flow, failure semantics dan deployment.

## 10. Keamanan, privasi dan regulasi

- **Threat model wajib:** tenant escape, token/tenant context spoofing, SSRF melalui device URL, CWMP/USP spoofing/replay, XML bombs, credential exfiltration, malicious CSV, improper approval, worker replay/duplicate, log/metrics/backup leakage, supply chain, custom domain takeover.
- **Defence in depth:** verify issuer/audience/signature/nonce, server-resolved tenant membership; tenant/device binding independen dari URL; application authz + DB RLS, service identity least-privilege, resource scoping di query dan queue, tenant-key/secret compartment, policy enforcement di ingress/API/worker/export/search.
- **Sensitive ops:** PPPoE mass change, reset/reboot, firmware, config write, import/export sensitif, secret read, role elevation dan cross-tenant support access harus diklasifikasi; approval dan blast-radius limits proporsional. Secret tidak boleh muncul di audit/event/ticket.
- **Compliance:** tentukan yurisdiksi pelanggan, data pribadi yang disimpan, dasar pemrosesan, retensi, lokasi data, kewajiban kontraktual dan audit sebelum penjualan. Dokumen ini bukan legal opinion atau sertifikasi keamanan. Detail di `SECURITY.md`.

## 11. Rencana tahap dan exit gate

| Tahap | Fokus | Exit |
|---|---|---|
| M0 (hari ini) | PRD/architecture/security/device matrix/ADRs/backlog | Dokumen siap version control; pilihan PROPOSED tidak disalahsebut APPROVED |
| S1 D1–D7 | Vertical slices MVP lab; baca `SPRINT_BACKLOG.md` | AC-01..07 dicatat, AC-08 jika node tersedia; demo & status akurat |
| M1, setelah sprint | ACS/USP protocol completeness terprioritas, physical interop, adapter read-only, end-to-end authz | Test matrix meningkat **per kombinasi**; ketiadaan perangkat tetap blocker |
| M2 | Batch provisioning controlled, diagnostics richer, UX tenant/custom-domain, operational hardening | Stage pilot tenant terisolasi + security review |
| M3 | HA DB, production K3s, DR/backup, threat verification, load/fault injection, SLO budgeting | Commercial readiness review dengan bukti SLO/RPO/RTO dan pentest |
| M4 | Paket/kuota, tenant onboarding self-service terbatas, observability/cost & scale tuning | Contract/compliance/support model disahkan sebelum penjualan luas |

Urutan M1–M4 berbasis dependensi/hasil tes, **tanpa janji tanggal atau klaim implementasi**.

## 12. Risiko dan asumsi

| ID | Risiko/asumsi | Dampak | Mitigasi / status |
|---|---|---|---|
| R-01 | Ketersediaan fisik/model/firmware tak tercatat | Klaim dukungan tak sah | Jalankan simulator terpisah, inventory fisik D1, buktikan per fitur |
| R-02 | Keterbatasan waktu 7 hari dan protokol kompleks | Scope terlalu lebar | Prioritas vertical slice, cut line S1, tidak menganggap scaffold selesai |
| R-03 | Multitenancy bocor di protocol/workers/backup | High-severity breach | RLS + service scopes + adversarial tests + no-go gate |
| R-04 | Timeout router menghasilkan unknown side-effect | Double provisioning/outage | Job state machine, reconciliation, idempotency, approval, low blast radius |
| R-05 | Single DB dan pilot node menjadi bottleneck/SPOF | Outage dan data loss | Backup/restore S1; HA/DR sendiri untuk komersial |
| R-06 | MQTT/broker/device MTP compatibility belum pasti | USP design bottleneck | ADR transport, PoC simulators & physical agent compatibility |
| R-07 | Cross-site/custom domain auth complexity | Session leaks/takeover | Verified domain, isolation, cookie CSRF, strict ingress mapping |
| R-08 | Diagnostik salah akibat missing/stale evidence | Salah eskalasi/remediation | Evidence, freshness, uncertainty dan human review |
| R-09 | RAM/disk/server proyeksi tanpa beban | Cost/perf surprise | Capacity questionnaire, baseline measurement, quotas/retention |
| R-10 | Implementasi multivendor melanggar vendor ACL/licence | Interop/legal/ops | Gunakan kanal terdokumentasi, uji authorized lab, review license |

## 13. Open decisions yang harus divalidasi

`DECISIONS.md` adalah daftar resmi dengan owner/decision deadline; prioritas teratas: (1) database tenancy dan backup tenant isolation; (2) USP amendment feature profile/MQTT broker & credential onboarding; (3) per-device CWMP authentication, NAT/connection request; (4) exact OLT/ONT/MikroTik inventory/akses; (5) identity/secret manager, domain ownership and data residency; (6) RPO/RTO, retention, tenant quotas dan load model; (7) tingkat approval dan peran matriks rinci; (8) supplier VPS/K3s/storage; (9) produk legal/commercial support scope.

## 14. Sumber dan jejak perubahan

**Sumber primer:** `IPAT_PROJECT_BRIEF.md` (transferred approved design baseline, 2026-09-25); Project Instructions IPAT. Verifikasi referensi publik pada 2026-09-25: Broadband Forum TR-069 Amendment 6 Corrigendum 1 dan TR-369 Amendment 5 sebagai versi *in force*, TR-181 Issue 2 Amendment 21, dokumentasi MikroTik REST/API, PostgreSQL RLS, Ubuntu 26.04 LTS, KEDA. Link rinci di `ARCHITECTURE.md`. Rujukan publik menginformasikan pilihan standar, **bukan** bukti perangkat IPAT kompatibel.

**Kontrol perubahan:** setiap perubahan lingkup → PRD dan backlog; perubahan teknis → ADR + ARCHITECTURE/SECURITY; hasil fisik → DEVICE_MATRIX; semua milestone → PROJECT_STATUS. Versi berikutnya baru berstatus approved setelah review owner dan para penanggung jawab yang ditunjuk.

### R5.9 interim restricted web demonstration (not new commercial acceptance)

The private web preview acceptance requires explicit owner opt-in, successful
same-machine localhost-only SSH tunneling, a functional first-party lab-only
browser status page, default route denial, CSP and HTTP negative tests.
No customer/tenant login or privileged menu may be presented without trusted
OIDC membership and approved RBAC+ABAC; production-domain TLS and physical
device support remain separate unfulfilled acceptance criteria. The original
commercial FR-002/FR-003/FR-004 and backup/K3s security gates remain binding.

### R6.0 hardware test intake slice and acceptance

Before physical device testing, the strictly private browser may list only
the eight already approved pilot *target categories*. Acceptance requires
zero phantom physically registered devices or compatibility claims;
exact model/firmware/board information must remain visibly unknown until
observed. The optional non-network offline credential-free intake validator
must reject unknown targets, ambiguous firmware, sensitive extra keys,
embedded addresses, duplicate JSON fields and unsafe output destinations;
output must remain unapproved, unconnected and outside Git. The existing
PRD's original real OLT/ONT/MikroTik and authenticated tenant-binding
functional acceptance is unchanged: only a later device-specific, owner-
authorized, evidence-backed physical test may promote an actual device.

### R6.1 concrete RouterOS customer unit first-read acceptance

The initially targeted DEV-08 customer-router SKU is operator-reported
RB951Ui-2HnD with RouterOS 7.23.7, still physically UNTESTED.
The first slice is **not** full device management: a distinctly
approved private HTTPS read-only first-contact probe of *this exact*
model/firmware, certificate and least-privilege verification, only
one system resource query, exact board-name/architecture/version
match and redacted private evidence. No subscriber data, configuration
read/export, PPPoE writes, firmware upgrades, Wi-Fi operations,
customer login or automatic enrollment are in this first acceptance.
Actual observed status cannot be promoted until human reviewer signs
off identity/tenant permission and the read evidence. Synthetic
negative tests alone must not pass physical TC-ROS-03.

### R6.2 native Rust RouterOS normalization acceptance (lab-only)

The initial customer RouterOS DEV-08 target may pass its first
**offline parser** acceptance only when the original Rust
`routeros-core` consumes the bounded expected read-only
/system/resource shape, verifies RB951Ui-2HnD/mipsbe/7.23.7
(with narrowly permitted release-channel suffix), rejects
duplicate/oversized/ambiguous response data, and emits no
sensitive/router-auth fields. A separate closed-schema staged
evidence parser must interoperate with the prior Python
allowlist-only first-GET helper without elevating the evidence.
This is not TC-ROS-03 actual physical acceptance and grants
no dashboard login, trusted tenant binding or configuration rights.

### R6.3 security acceptance for a remotely accessible customer router

Even explicit customer test approval is insufficient to authenticate if the remote SSH server host fingerprint differs from the owner-Mac pinned key. A single-host unauthenticated fingerprint preflight must refuse to send passwords or execute read-only commands after mismatch or absence of trusted historical proof. Comparison against a *different trusted direct-LAN path* and deliberate owner acceptance are required before a separately scoped login; scanning the same public path cannot satisfy independent identity verification. No automatic known_hosts rewriting, disabled host checks or product feature compatibility status upgrades are permitted. See [R6.3 security evidence](MIKROTIK_SSH_HOST_TRUST_R63.md).

### R6.4 customer-router SSH first-contact acceptance (lab, not physical)

Provide an optional strictly local, default-OFF SSH
first-inventory path without ever accepting a password,
public-only RSA scan as identity proof, unknown vendor
commands, mutable router operations, shared host trust
rewrite, or automatic tenant enrollment. Real execution
requires independent trusted direct-LAN fingerprint
match, explicit key-change acknowledgment, approved
single customer test/recovery, dedicated least-privileged
SSH key and local owner opt-in; an unexpected fingerprint
must fail closed before any authentication. Exactly
one immutable three-field read is allowed, and its
sanitized result must pass the existing Rust closed-schema
verification with all physical enrollment, tenant and
configuration permissions FALSE. The owner-only private
preview MUST explicitly show SSH identity blocked
while the missing physical evidence remains unresolved.
Unit/CI synthetic test completion is not actual physical
DEV-08 interoperability.

### R6.6 native CWMP first read RPC and synthetic session acceptance

Partial fulfillment of FR-009/010 and AC-03:
original Rust now supports a **narrow synthetic**
SOAP 1.1/CWMP 1.0 `GetParameterValues`
request plus bounded, correlated, type/namespace
validated one-value response or numeric-only
CWMP fault. Only exact
`Device.DeviceInfo.SoftwareVersion` can be
read in this profile. The existing sealed
peer/tenant admission state is extended
with the genuine empty-POST transition,
one session read and same peer/lease
correlation/abort. An actual Rust Axum
process can temporarily handle a private
127.0.0.1 synthetic HTTP Inform parser
probe but unconditionally denies authentic
`/cwmp` ingress and performs no enrollment.
Acceptance is **simulator-only** until real
client mTLS, trusted enrollment, durable
CWMP HTTP sessions/queue and an authorized
one-ONT exact-firmware hardware test all pass.
Original Rust ACS and separate native USP
remain binding; no full commercial ACS

completion claim is accepted from unit tests.
[Exact R6.6 evidence](ACS_CWMP_R66.md).

### R6.7 autentikasi mTLS asli — laboratorium saja

ACS Rust kini memiliki bukti
aktual TLS1.3 mutual TLS di
proses terpisah hanya 127.0.0.1,
dengan client CA yang diverifikasi,
sertifikat klien wajib dan uji
negatif tanpa cert/CA salah/
EKU salah/identitas server salah.
Ini *partial implementation*
FR-009 transport cryptography,
bukan penyelesaian FR-009
atau AC-03 karena perangkat
dan tenant belum dikaitkan
secara aman dan semua /cwmp
real tetap 503. Enrolment
tepercaya dan sesi CWMP
durable, authenticated
Inform/InformResponse/read
pada satu ONT nyata dengan
model/firmware tercatat
tetap MUST dan NOT DONE.
[Detail R6.7](ACS_MTLS_R67.md).

### R6.8 validasi rancangan tiga dashboard (belum produksi)

Preview privat Platform Admin,
Tenant Admin dan NOC tersedia
dari satu backend dan frontend
laboratorium tanpa data pengguna
atau perangkat asli. Menu dan
metrik menggunakan skenario
ilustratif, bukan role
sungguhannya. Endpoint API
nyata per area platform/
tenant/operations selalu
HTTP 401 untuk setiap metode
dan header identitas palsu.
Kebijakan Rust referensi
deny-default memisahkan
platform-only metadata,
tenant dan POP, namun
belum jadi authenticated
runtime middleware.
Kriteria acceptance:
UI dan tombol hanya
berfungsi sebagai mockup,
backend tetap menolak

akses tidak terverifikasi,
status tidak mengaku
pelanggan/perangkat aktif.
FR-002 autentikasi, FR
perusahaan/tenant, menu
terfilter dengan identitas
valid, operasi data nyata
dan operasional ISP masih
MUST terblokir.
[Detail dan gate](DASHBOARDS_R68.md).

### R6.9 partial identity proof for Platform/Tenant/NOC (not login)

FR-002/003 advance from visual synthetic dashboard
to a cryptographically verified, externally
pinned RS256 JWT subject **on private
explicitly opted-in laboratory only**.
Signature, issuer, audience, key ID,
expiry, nbf/iat and token lifetime
checks are exercised using disposable
OpenSSL RSA test identities, including
forgery and algorithm-confusion negatives.
Valid signature yields NO tenant/role
privilege and real business endpoints
remain HTTP 401. Thus FR-002 authenticated
OIDC session with MFA, FR-003 resource
authorization and full verified
domain/tenant isolation are **not yet
accepted**. Before dashboard users
can actually log in, integrate real
IdP discovery/JWKS lifecycle,
Authorization Code+PKCE, host-bound
cookies, verified DB membership,
server-side filtered menus and

same-tenant/POP backend authorization
against PostgreSQL RLS.
[Exact R6.9 gap/test plan](IDENTITY_OIDC_R69.md).

### R7.0 — tahapan nyata ketiga dashboard dan isolasi identitas

- Tahap sekarang hanya kandidat skema keanggotaan
  tenant, POP dan platform di PostgreSQL
  laboratorium. Runtime database role belum
  mendapat hak baca terhadap tabel identitas;
  endpoint dashboard nyata tetap menolak
  seluruh pengguna sampai independen
  diverifikasi dan diotorisasi.
- Penambahan ini **belum** memenuhi
  FR-002/003/005 atau AC-01 sebagai
  jalur UI+API+DB terintegrasi. Tes DB
  negatif hanya bagian kontrol terisolasi.
- Prioritas MUST selanjutnya:
  OIDC Authorization Code+PKCE/MFA,
  keanggotaan disetujui terpisah dari
  token claim/HTTP headers, mapping
  verified tenant/domain/POP, server
  RBAC+ABAC yang menyaring menu dan
  menolak URL/API, RLS dan audit.
  Sertakan tes penetrasi silang dua
  tenant dan tiga workspace.
- Waktu perkiraan bersyarat ada di
  [roadmap R7.0](DASHBOARD_MEMBERSHIP_R70.md);
  tidak ada rilis komersial sebelum

  gate recovery/perimeter dan perangkat
  laboratorium nyata lulus.

### R7.1 user-requested DEV-01 ZTE C320 early pilot and firmware change (scope alert)

FR-016 accepts simulator if physical OLT is unavailable. Pure
offline parser and red safety alert are partial implementation,
NOT actual device integration or TC-OLT-01 completion.
FR-017 prohibits enabling writes on an untested exact tuple.
The additional user request for firmware upgrade is NOT a
previously promised first-week MVP feature. It is now tracked
as a proposed high-impact extension, with independent owner
authorization, exact vendor release/card compatibility,
authenticated private transport, onsite recovery, validated
backup/restore, approved maintenance window and two-person
approval before any actual write feature could be implemented.
Any mismatch is conspicuously RED on all three dashboard previews.
See PRD_DEVIATIONS_R71.md for the requirement-by-requirement audit.

### R7.2 target DEV-01 firmware integrity, not an early upgrade commitment

FR-016 S1 permits C320 simulator
read-only evidence if real OLT
is unavailable. Local SHA-256
integrity of a synthetic or
operator-private image is now
available through a fully offline,
non-executable check. It does NOT
meet FR-017 per-model/firmware
validated write operations,
nor TC-OLT-01/TC-OLT-FW-01
physical test acceptance.
Actual board/firmware inventory,
manufacturer image origin,
recovery, maintenance/impact
window, dual approval and
post-change physical tests
remain missing. No automatic
firmware upgrade is permitted.
This request is outside
guaranteed initial 7-day MVP
and remains gated by original
high-risk security policy.
See [visible red PRD gap

and R7.2 procedures](C320_FIRMWARE_INTEGRITY_R72.md).


## R7.5 rollout scheduling clarification, 2026-09-27

Product owner has expressly requested delaying FR-004 subdomain and
custom-domain verification and **domain-specific** session isolation until
after an integrated private laboratory runs correctly. This is scheduling,
not deletion or weakening of FR-004/AC-09, which remain mandatory before
customer public-domain onboarding (ADR-020). Existing FR-004 priority C
and the commercial stage are unchanged.

**SECURITY INVARIANT:** FR-001/002/003 and AC-01/02 tenant data and
authorization isolation are NOT delayed. Shared private lab URL is not an
identity provider, domain verification, or an alternative to server-trusted
tenant membership. Business endpoints remain HTTP401 until real verified
OIDC/MFA, POP membership and denial-at-menu/API/DB/job are proven. Two
synthetic tenant negative tests remain baseline S1, independent of DNS.
An unverified domain cannot be used to serve tenant data. No new approved
public deployment, firmware operation or physical compatibility claim.
See LAB_FIRST_DOMAIN_LATER_R75.md and DECISIONS.md ADR-020.


## R7.6 owner-provided product/domain illustration

Product owner identifies hub.example.invalid as the INTENDED later Fadly
customer custom domain and ipat.id as the INTENDED later commercial
platform identity (ADR-021). Neither is independently verified for
DNS ownership, TLS or public tenant onboarding. hub.example.invalid is
currently also the known lab VPS SSH hostname: do not change its
routing until trusted alternative management/rollback exists.
FR-004 and AC-09 remain commercial-domain requirements scheduled
after functioning private system per ADR-020. FR-001/002/003
tenant-data and authorization isolation remains mandatory NOW,
regardless of custom-domain timing or DNS assumptions.
The R7.6 synthetic issuer+subject-to-candidate-row Rust policy
bridge is NOT a real authenticated company dashboard.


## R7.7 database membership isolation candidate (no scope change)

Read-only DNS now resolves hub.example.invalid A to the observed
laboratory server public IPv4; owner says they pointed the domain.
Neither this A record nor prospective custom-domain branding
proves ownership, TLS routing, or authenticated tenant isolation.
ADR-020 postpones only commercial FR-004 customer-domain
verification; FR-001/002/003 remain S1 mandatory.
R7.7 introduces an independently tested *synthetic-only*
restricted PostgreSQL identity lookup candidate with exact
issuer+subject+tenant+role+POP matching and deny-by-default
privilege tests. It does NOT implement real OIDC/MFA membership
provisioning, integrated menu/API/worker/RLS isolation or
commercial-domain AC-09. No existing acceptance case is
claimed complete by these narrower synthetic tests.


## R7.8 partial private end-to-end identity acceptance proof

R7.8 now joins the existing pinned RS256 verifier, restricted exact
PostgreSQL identity membership lookup and fail-closed tenant/POP
read-only menu policy inside the real Rust Axum binary, guarded
by two explicit nonroot private-only opt-ins and a Unix-only
DB connection. A disposable PostgreSQL CI login role is the
ONLY newly created login identity; this is an integrated
synthetic pilot, not a real Keycloak MFA user or company tenant.
Per-tenant JWT custom claims, request Host and forged headers
remain untrusted, with real business APIs HTTP401.
FR-001/002/003, AC-01/02 are PARTIAL until actual human
IdP/MFA, operator-approved memberships, live persistent backend
API/RLS/queue scoping and complete negative E2E tests pass.
FR-004/AC-09 remain M2 commercial domain verification per
the owner-approved ADR-020; customer DNS pointing alone does
not enable a domain or a platform role.


## R7.9 approved remote OLT / provider-independent K3s clarification

The owner explicitly prefers IP-reachable remote
ZTE C320 management over local physical L1/console
for initial **READ-ONLY** access. FR OLT inventory
MUST provide supported remote management channels
(vendor-documented SSH CLI, SNMPv3 when independently
verified on exact firmware) and NEVER assume
a vendor-independent OLT-side TR-069 API.
Exact DEV-01 firmware/board/CLI/MIB remains
UNTESTED until the real connection occurs.
R7.9 guarded remote SSH candidate adds real
two-command transport code; synthetic tests
alone do not close physical DEV-01 TC-OLT-01.

K3s MUST permit separate VPS providers/heterogeneous
worker hardware without a cloud-vendor firewall
integration dependency. OPTIONAL host firewall
is permitted but a totally unprotected internet-facing
K3s control/CNI plane is not accepted. Supported
pilot topology candidate is single private node
or one same-site server plus independently
authenticated private-VPN workers in different
providers. No user request changes the external
recovery/restore gates before live host install.
R7.9 delivers a strict OFFLINE topology planner,
not actual cross-provider measured scaling.


## R8.0 virtual pre-device acceptance step (not hardware interoperability)

Owner explicitly approves continuing software development
while the laboratory devices are offline. The next
integrated virtual-lab MUST prove a cryptographically
verified short-lived synthetic JWT for one lab operator
with valid NOC memberships in TWO synthetic ISPs:
each explicit tenant+POP returns ONLY that ISP's
devices from an ACTUAL disposable PostgreSQL database
through REAL Rust Axum and restricted SQL security.
Cross-tenant/POP/role, expired/revoked, unsigned,
forged Host and unapproved platform impersonation
must fail closed; no real data HTTP API or firmware
action is enabled. R8.0 implements sealed private
`/lab/auth/devices` read-only bounded inventory.
Before real customer delivery, a real MFA IdP,
trusted approver workflow, independently scoped
production data/API/queue, complete dashboard
rendering, physical C320 firmware/CLI and
ONT/RouterOS interoperability, multi-node
K3s measurements and offsite whole-host
database/etcd recovery remain MUST items.
Software simulated acceptance can be
completed prior to external device tests;
simulator success does not certify actual
equipment or production readiness.


## R8.1 native USP protobuf pre-device software acceptance

Native TR-369/USP requirement progresses
from opaque domain-only synthetic correlation
to REAL BBF v1.4 protobuf Record/Get
serialization and strict GetResp
structural parsing. A separately manually
encoded independent binary golden fixture
MUST match the Rust `prost` offline
Get byte for byte, and valid independent
GetResp MUST parse through the actual
Rust process on real Ubuntu26 loopback.
Negative duplicate protobuf oneof,
unknown session, unsupported message
type, malformed/oversize, forged claimed
agent, wrong simulated tenant/verified
mock peer, and replay MUST NOT grant
a session or device write. The explicitly
opted-in private parser MUST never echo
raw parameter values or endpoint IDs and
must not be mounted at all on K3s
public lab binds. Only real tested
TLS/MQTT endpoint and approved
enrollment may later be connected
to the restricted virtual domain.
TC-USP-01 actual authenticated agent
interop remains **NOT RUN**, even
if the entire R8.1 software slice
passes CI.


## R8.2 original virtual ONT hardware-free SOAP acceptance

The software-first original Rust ACS MUST demonstrate
actual loopback HTTP handling of a FIXED synthetic CWMP
1.0 Inform→InformResponse and a separately generated
GetParameterValues request with a separately parsed
correlated response/fault. It MUST deny non-synthetic
identity, disallowed methods/parameters, malformed,
DTD, duplicate and oversized input, leak no fake
device values and leave the production device /cwmp
endpoint disabled. The virtual proof MUST require
separate opt-in and never activate from public K3s.
CI MUST exercise the actual compiled Rust binary
through a real local HTTP socket with an independent
Python XML validator. These are strictly virtual
software-acceptance scenarios and NOT a substituted
TC-CWMP-01 result against the actual VSOL/ZTE ONT.
Actual certified onboarding, persistent sessions,
actual physical interoperability, broad RPC
coverage and production release remain MUST.


## R8.3 visible device registration and adoption preparation acceptance

The owner requires visible Add Device, Device List
and Device Status sections before first actual
ZTE C320/C-DATA/VSOL/ZTE/MikroTik testing.
MUST R8.3 deliver a real browser→Rust localhost
lab UI and API allowing fake candidates to be
added, listed, filtered and removed; every
unverified candidate MUST show pending review,
connectivity unknown and health not measured,
NOT simulated-online data disguised as hardware.
MUST provide a separately gated actual signed
JWT→two independently privileged PostgreSQL
candidate-create/read draft path with exact
approved tenant-admin origin, own-tenant/POP
read scope, idempotency, optional RFC1918-only
management metadata and no credential/write
RPC or firmware. MUST test both independent
ISP tenants and a NOC role constrained to exact
approved POP against a REAL disposable DB and
REAL Rust HTTP, including forged tenant/Host,
unauthorized role, revocation, IP and replay
negative assertions. Public/real SaaS operations
remain 401 and physical adoption is NOT
declared ready without real MFA, high-risk
approval, live verified peer binding,
vendor firmware interoperability and
independent offsite disaster recovery.


## R8.4 — identity/MFA review stage and maker-checker metadata acceptance

Before physical adoption, two separately authenticated tenant
people MUST participate: an approved tenant_admin may propose
a pending candidate; a distinct approved security_admin
with a short-lived PINNED-SIGNED JWT carrying exact `amr:mfa`
MUST approve/reject candidate metadata. Reviewer is never
authorized merely by untrusted token role or Host.
The DB MUST check the exact issuer/subject, active own
tenant and distinct human every request, use a row lock,
append immutable audited review reason/idempotency evidence
atomically and reject cross-tenant/revoked/expired/self approval.
Metadata approval MUST NOT enqueue physical reads,
change UNKNOWN health, enroll/operate firmware or
magically grant real user MFA. CI on real disposable PG
plus actual signed Rust Axum tests is the software
acceptance; real IdP/BFF hardware adoption remains BLOCKED.


## R8.5 independent real human IdP onboarding preflight

MUST authenticate future operators with an independently
approved OIDC IdP using proper second-factor enrollment,
confidential Authorization Code+PKCE browser BFF,
server-only session and exact DB-approved tenant/role/POP
membership; no protected menu without matching backend
authorization. A signed `amr:mfa` claim from a pinned
issuer is necessary reviewer evidence but is NOT alone
proof that an actual customer IdP configured and
challenged an independent second factor.
As prerequisite source acceptance, an original Rust
nonroot CLI MUST verify exact pinned short-lived signed
RSA issuer/audience/kid and `amr:mfa` from protected
stdin, reject unsafe key files and never print identity,
session, token, tenant or roles. This preflight utility
is NOT a substitute for actual human MFA or real
customer login and MUST NOT activate a production endpoint.


## R8.6 browser OIDC S256 PKCE initiation guard (MUST readiness, lab-only)

Original Rust browser BFF MUST initialize signed-in flows
with OS-CS-PRNG, independent 256-bit state/nonce/PKCE,
RFC7636 S256, exact owner-pinned HTTPS issuer authorization
endpoint, registered redirect, bounded five-minute pending
state and browser correlation cookie; mismatched Host/cookie,
unknown query, replay and expired state MUST fail closed.
Until actual operator-approved IdP, human MFA enrollment,
confidential server-side code redemption, nonce-verified
ID token, secure session and checked exact PostgreSQL
tenant/POP membership, every callback MUST reject login,
and every real device API MUST remain denied. Passing
cryptographic synthetic browser tests is NOT real human
login or an approved physical adoption prerequisite.


## R8.7 OIDC browser backend signed token binding — MUST subcriterion

Before real operator login, after provider-certified
confidential S256 code redemption, the original Rust
service MUST independently validate pinned-RS256
issued access+ID tokens against their distinct
approved audiences, shared signed issuer/subject,
R8.6 privately stored nonce and at_hash of the
exact access JWT. It MUST refuse wrong signing key,
typ confusion, stale auth_time and absent validated
MFA, and MUST NOT derive tenant roles from OIDC
claims. At this milestone implement the pure
OFFLINE original verified pair function and independent
genuine ephemeral-RSA negative tests, but keep
real login/BFF session and hardware review
disabled until actual IdP and enrolled human MFA
plus separately authorized SQL membership exist.


## R8.8 identity-first device dashboard acceptance

Before physical device adoption or the authenticated
commercial Device Manager, independently signed
matching issuer/subject ID and access tokens
MUST bind to private server nonce, reviewed
MFA semantics and exact sealed SQL active
tenant/POP membership. An opaque browser
session MUST never embed or trust JWT roles,
tenant Host, POP claim or API headers;
each requested resource MUST independently
recheck current database membership.
Write endpoints MUST require independently
verified trusted HTTPS origin and anti-CSRF
proof in addition to the session and DB.
An OFFLINE compiled signed+real disposable
PostgreSQL two-company integration test
may validate the design, but shall NOT
pass real-human-MFA or customer-readiness
acceptance until an external real IdP,
confidential code exchange, real approved
membership and Secure browser callback
are independently verified. Current
physical hardware admission remains BLOCKED.


## R8.9 session-scoped real PostgreSQL candidate inventory checkpoint

MUST: The eventual authenticated tenant Device Manager
shall bind individually verified OIDC ID/access JWTs and
an independently authorized real-human MFA claim to
a cryptographic opaque short-lived BFF session and
actual restricted PostgreSQL membership. Every
candidate listing must RECHECK exact tenant/POP/role
authorization in a single SQL snapshot; a cookie
alone grants NO permanent role, device entitlement
or access to management IP/secret/telemetry.
Acceptance now: independent disposable real
PostgreSQL two-company positive/negative
integration for this ORIGINAL Rust bridge.
An unmounted software bridge does NOT fulfill
the production dashboard, real MFA or live
device interoperability acceptance criteria.


## R9.0 actual site-link intake before physical OLT adoption

MUST: track source-specific network reachability independently
from verified physical device identity and trustworthy health.
One owner-authorized public TCP321 endpoint replied to Mac
but the actual VPS source timed out, so no true IPAT worker
access or device adoption is accepted. Public plaintext Telnet
MUST NOT transmit device credentials; support only one explicit
no-auth, read-only initial transport observation and never
convert an unverified vendor banner into compatibility.
Next MUST: verified private encrypted management path or
independently authenticated vendor secure protocol,
actual MFA, tenant/POP mapping, maker-checker approval,
and strictly read-only real model/firmware evidence.
The visible Device Manager MUST label these R9.0 facts
as time-limited historical transport observations,
not live device connectivity/health.


## R9.1 adoption-readiness evidence before any physical read

After maker-checker metadata approval, a candidate MUST remain unable
to trigger a physical read until four fresh independent readiness
gates are verified: secure management path, physical device identity,
dedicated read-only account and recovery plan. The latest evidence
for each gate MUST be append-only, time bounded and tenant scoped;
a later blocked or expired gate MUST fail closed. Metadata approval
alone MUST NOT imply connectivity, health or physical permission.
A safe projection may expose only gate booleans and a derived
read_probe_eligible flag. That flag MUST NOT itself enqueue,
execute or authorize network I/O. Browser/session access MUST still
recheck current exact tenant/POP membership and real-human MFA/BFF
remains a separate production gate.


## R9.2 hardware-free durable first-read request criterion

MUST distinguish operator's nonexecuting read-only
probe REQUEST from both four-gate readiness and
an independently approved actual transport dispatch.
Acceptance: real disposable two-tenant/POP SQL
demonstrates no intent before separate maker/checker
approval+all four latest valid readiness gates,
correct current NOC POP and authenticated signer;
one immutable per candidate with exact idempotent
retry and same-transaction private audit; later
block cannot create another. The unmounted signed
ID/access opaque BFF method separately requires
trusted Host/Origin, CSRF and fresh SQL membership.
No customer/public listener, worker, queue consumer,
real credentials, Telnet login or physical health
claim is enabled by this milestone.

## R9.3 proposed secure physical C320 site-access gate

MUST NOT treat owner-provided publicly NATed Telnet TCP/321 as an
authenticated, encrypted or worker-reachable management route. Before
any login or actual physical read: verify owner-authorized secure site
transport and isolated last hop, independent host/device identity,
restricted read-only account, exact tenant/POP and NOC reviewer,
restricted actual nonroot worker reachability and fresh R9.1 gate
revalidation. Keep R9.2 stored intents permanently nonexecutable.
Record SITE-01 through SITE-06 evidence in
`docs/R93_C320_SECURE_SITE_ACCESS_GATE.md`. Firmware mutation remains
a separate prohibited high-risk workflow pending explicit authorization.

## R9.4 RouterOS 7 site-gateway predeployment (offline only)

Owner confirms a RouterOS 7 gateway exists, but its patch version,
private C320 management VLAN and recovery access remain unverified.
MUST limit any eventual WireGuard tunnel to one authorized site and
private OLT host, with verified isolated final plaintext Telnet hop,
no unrestricted customer/VPS route, explicit safe rollback and
separate approval to disable public Telnet NAT. No direct live
configuration is enabled by the offline R9.4 planner.

## R9.5 approved optional tunnel selection and Tenant Admin UX direction

WireGuard is optional, not a prerequisite for every IPAT tenant or
RouterOS version. Tenant Admin MUST eventually manage per-site
connection choices through authorized UI with backend review, including
SSH/SNMPv3 authPriv, WireGuard, compatible IPsec and an IPAT gateway.
Public Telnet MUST never become an authenticated management transport.
R9.5 delivers only a clearly marked isolated LAB preview selector,
NOT saved configuration, production tenant access or OLT adoption.

## R9.6 safe-as-live OLT staging, backend plan check

Treat DEV-01 as carrying active distribution traffic: NO discovery
sweep, automatic login, firmware, configuration command or bulk ONU
poll from the public Telnet endpoint. R9.6 MUST provide a nonexecuting
backend-validated selection UI while live transport and MFA remain
gated. Acceptance: real Axum tests deny missing origin and injected
credential fields, reject public Telnet/RouterOS6 WireGuard, allow
review-only eligible plan with zero network actions and no device
adoption. Physical TC-OLT-01 requires independently accepted isolated
last-hop, exact hardware identity and measured no-impact baseline.

## R9.7 durable own-tenant network draft acceptance (NOT provisioning)

After verified active tenant-admin membership, ONLY one immutable
nonexecutable method/gateway draft per exact own candidate/POP may be
stored with exact idempotent retry and same-transaction audit. SQL
distinct no-login EXECUTE writer and restricted own-tenant reader must
not gain raw table rights. No endpoint/secret/route or job is accepted;
provisioning_enabled permanently false. Any proposed actual tunnel
configuration, VPN key or live OLT probe is a SEPARATE milestone.

## R9.11 LIVE C320 pre-adoption fail-closed acceptance

MUST expose observed credential-free SSH handshake separately from
actual physical adoption/health. Display each missing gate on the
private lab screen, with no credential input or activation controls.
Before actual authenticated adoption, require independently pinned
host key, proven isolated last hop, restricted read-only account,
exact firmware command allowlist, baseline/abort owner and worker
private route. Never auto-provision customer ONTs or touch live OLT
configuration during first-read admission. Transport evidence alone
MUST NOT change connectivity=UNKNOWN or health=NOT_MEASURED.

## R9.12 WireGuard tenant-wizard synthetic safety gate

SHOULD provide a dashboard-led tunnel planning interface that
communicates missing isolated management LAN, console restore test,
observed service baseline, real signed MFA, maker/checker and pinned
vendor SSH identity. LAB prototype MUST NOT treat scenario selections
as evidence or generate/apply configuration and must reject unlisted
fields. Real tunnel activation remains MUST but NOT IMPLEMENTED and
requires a separate approved implementation milestone.

## R9.13 production-like live C320 one-command first read

Actual live initial C320 authentication MUST prefer one single
bounded read-only identity/inventory operation before any subsequent
version or ONT poll; no default factory/privileged account is allowed
by the dedicated read-only collector. Simulated CLI and route-table
proof do not count as physical adoption or a no-customer-impact test.

## R9.13 private laboratory observed physical candidate display

MUST distinguish physical transport observations from registered,
independently authenticated operational inventory. When evidence is
bounded but incomplete the dashboard MAY show a separate historical
owner-reported physical candidate, ONLY in the private lab, with
UNKNOWN connectivity/health, no site/POP assignment and no operational
buttons. This does NOT satisfy the genuine tenant adoption acceptance.

## R9.14 independently evidenced physical onboarding (MUST, staged)

In addition to existing four metadata adoption checks, require SIX
separately time-bounded genuine site proofs: trusted OOB SSH host key,
isolated last hop, dedicated restricted account, firmware exact
read-only command, observed live baseline/abort and independently
verified worker route. Metadata alone MUST NEVER make physical
worker executable, mark hardware adopted or health healthy. A fresh
blocked or expired gate denies readiness; a separate authorized
one-command physical observation, audit and verified on-device model
and firmware is required to transition to operational inventory.

## R9.15 Site A/IPAT central tunnel ownership — binding product refinement

MUST treat IPAT/dashboard as Site A central hub; do not push router
configuration to Site B. After REAL signed scoped Tenant Admin MFA,
Site A SHOULD prepare a reviewed downloadable pairing profile containing
only Site A's independently reachable endpoint, its public key,
nonoverlapping peer /30, one approved management host /32 and relevant
narrow routes. Site B operator independently generates/retains its
own private key, supplies only its public key and applies the reviewed
profile locally. Site A locally stages its own listener only after
independent approval, recovery and verified topology. Choose direct
private connectivity (no tunnel required) ONLY when the actual
bidirectional management path and isolation are independently verified;
for an external site use a reachable public Site A endpoint unless
an approved private cross-site route actually exists. Never equate
private address syntax with proven private reachability. R9.15 is
LAB-only fixed-choice UI + offline nonexecuting review, NOT actual
server activation, Router B export or real physical OLT adoption.

R9.15 additional SHOULD: Central Site A can derive a **disabled,
review-only** Site B RouterOS7 pairing package from validated topology
and separately provided PUBLIC keys. Site A and Site B each retain
their own PRIVATE keys. No Site A remote push, wide default AllowedIPs,
unsafe export QR defaults or automatic route/firewall modifications.
Actual signed Tenant Admin profile download and separately approved
Site A local activation remain MUST/NOT IMPLEMENTED.

## R9.16 Site A-owned pairing proof (SHOULD completed in DEV LAB ONLY)

IPAT Site A MUST own the central private key and the eventual
listener. Site B MUST own its own key and apply B config LOCALLY;
never permit central router configuration push. A same-network site
with independently proven private routing SHOULD use direct-private
without a VPN; outside sites need independently reachable public Site
A endpoint or proved existing routed private interconnect. Developer
lab MAY display Site A public key and render nonexecuting, disabled
B peer review using B PUBLIC key only. DEV-only local files do not
satisfy production vault backup, real MFA, signed approval, stable
listener or physical device adoption acceptance.

## R9.17 — Koreksi protokol adopsi direct-first (MUST)

Pilihan koneksi OLT/ONT/router adalah **per adapter/firmware** dan
memprioritaskan HTTPS tervalidasi, RouterOS API-SSL, SSH host-key
tepercaya, SNMPv3 authPriv dan ACS/USP sesuai kemampuan perangkat
sebenarnya. Bila rute jaringan yang sudah tersedia bisa digunakan
dengan keamanan yang dibuktikan, **WireGuard atau tunnel lain TIDAK
WAJIB**. Menu operasional menggunakan istilah *Server Pusat IPAT*,
*Gateway Lokasi*, *Jaringan Manajemen*, *Protokol Perangkat*,
*Kandidat Perangkat*. Internal contoh `site_a/site_b` bukan label
produksi. API-SSL MikroTik tidak boleh dianggap API-SSL umum ZTE.
Satu uji port atau sukses TCP tidak memenuhi adopsi fisik; penerimaan
mensyaratkan independen key/certificate+isolasi+akun terbatas,
observasi read-only sesungguhnya dan baseline customer.

## R9.19 — Katalog fungsi C320 berbasis bukti

Dashboard operator MUST menampilkan status per fungsi dan alasan
penolakan dari backend, bukan menganggap SSH yang terjangkau sebagai
adopsi. Tahap awal: pembacaan kartu dan firmware hanya setelah
identitas/firmware, role perangkat minimum, tenant+POP MFA dan baseline
terverifikasi; alarm, ONT dan optik membutuhkan uji firmware asli.
Provisioning, reboot dan upgrade firmware wajib maker-checker,
backup/restore dan pengendalian jendela perubahan. Endpoint LAB
R9.19 hanya menyediakan katalog dan MUST menolak semua POST aksi
fisik; tidak ada worker atau credential perangkat di frontend demo.

## R9.20 trusted-console host RSA pin handoff (MUST for first actual C320 read)

A real device host-key RSA public key MUST be obtained via an independently
trusted local chassis console or authenticated owner inventory, NOT by
SSH scan/TOFU. An offline matching check MAY generate an exact
single-host, owner-only 0600 `known_hosts` file but SHALL NOT
implicitly approve SSH login, real `show card`, OLT adoption or any
configuration action. Independent provenance/reviewer, least-privilege
account, isolated last-hop, true tenant OIDC MFA and live baseline
remain distinct prerequisites. See `docs/R920_C320_TRUSTED_CONSOLE_PIN.md`.
