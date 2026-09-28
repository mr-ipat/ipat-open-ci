# PERINGATAN MERAH — Gap PRD dan Pengujian ZTE C320 (R7.1)

**26 September 2026 · Developer: Mr. iPat · KEPUTUSAN: NO_GO OLT FISIK / FIRMWARE**

> **BELUM TERPENUHI:** Dashboard tiga ruang kerja masih pratinjau privat; OLT
> ZTE C320 fisik belum pernah terhubung, diperiksa atau diperbarui firmware-nya.
> Tidak boleh ada klaim kompatibilitas, dukungan firmware ataupun SLA.

## Audit terhadap PRD asli, bukan rekaan persyaratan baru

| PRD / Target | Status terverifikasi | Kekurangan |
|---|---|---|
| FR-016, DEV-01 ZTE C320 dan TC-OLT-01 | Target terdaftar; parser Rust dua perintah READ-ONLY sintetis R7.1 | Tipe kartu, firmware, akses tepercaya dan discovery nyata belum ada |
| FR-017 adapter per versi/protokol/fitur | Tidak ada tuple perangkat nyata validated | Terlebih dahulu perlu satu perintah aman terbukti pada actual C320 |
| FR-001..006 dan FR-029 tiga dashboard | Tiga pratinjau privat; API bisnis tetap HTTP 401 | Real OIDC MFA, membership tenant, POP, RBAC+ABAC/RLS dan telemetry |
| FR-009/010 ONT lewat ACS asli | Rust parser, mTLS dan RPC hanya terbukti di laboratorium | Belum ada ONT sungguhan dan sesi HTTPS CWMP+tenant yang valid |
| Permintaan update firmware hari ini | Tambahan BERISIKO TINGGI, bukan jaminan S1 dalam Project Brief | Image resmi cocok tiap kartu, hash, restore, approval, jadwal, rollback belum tersedia |

**Pembedaan penting:** FR-016 secara eksplisit mengizinkan simulator bila
perangkat fisik belum tersedia. Parser baru itu progres yang mematuhi
cakupan MVP, tetapi TIDAK memenuhi harapan menghubungkan OLT nyata.
Firmware update tidak dijanjikan pada tujuh hari pertama; keamanan
perubahan tetap tunduk FR-017, RBAC/ABAC dan approval PRD.

## Implementasi R7.1 yang sebenarnya

- Rust crate olt-core hanya memproses teks transkrip sintetis dua
  calon perintah baca: show card dan show version-running. Tidak memiliki
  driver jaringan, kredensial, upload, firmware execution ataupun
  endpoint tulis; WRITE_ENABLED tetap false.
- Parser memakai batas output, menolak control characters, format
  yang tidak dikenal, slot ganda, versi ganda dan input berbahaya.
  Output terstruktur hanya posisi, jenis, status kartu serta versi.
  Parser TIDAK menyimpan transkrip, serial ataupun secret asli.
- Firmware review adalah pemeriksaan kelengkapan bukti pada sisi
  software saja: hasil maksimal HumanReviewOnly, BUKAN boleh upgrade.
  Boolean yang dimasukkan ke software bukan pengganti bukti independen
  atau tandatangan persetujuan manusia.
- Ketiga dashboard privat menampilkan banner MERAH BESAR tentang
  ketidaksiapan nyata, TC-OLT-01 dan upgrade firmware tertahan.

## R7.2 batas tambahan yang sudah diuji — bukan pemenuhan firmware

Pemeriksa SHA-256 lokal baru dapat menerima berkas operator
pribadi dan menghitung kecocokan terhadap checksum **yang
dipindahkan operator sendiri**. Ini bukan autentisitas vendor,
kecocokan kartu, bukti firmware target atau izin upgrade.
Program tidak memiliki koneksi atau aktuator jaringan.
Banner merah pada ketiga pratinjau dashboard tetap berlaku
meskipun tes ini hijau. Lihat
[C320_FIRMWARE_INTEGRITY_R72.md](C320_FIRMWARE_INTEGRITY_R72.md).

## R7.3 — format dua nama kartu hanya pada parser offline

Dokumen vendor historis menampilkan perbedaan CfgType/RealType
pada satu slot. Importer sebelumnya menolak contoh sintetis yang
valid karena hanya membandingkan RealType. R7.3 kini menuntut MVR
dengan CfgType ATAU RealType dari **slot yang sama**; tipe acak,
slot berbeda dan tanpa MVR tetap gagal. Ini hanya memperbaiki
keterbacaan bukti OFFLINE, bukan kompatibilitas firmware/perangkat.
Bukti tes dan keterbatasan: [R7.3](C320_BOARD_ALIAS_R73.md).
**PERINGATAN MERAH TETAP BERLAKU: OLT FISIK BELUM TERHUBUNG
DAN FIRMWARE TETAP DINONAKTIFKAN.**

## Gerbang agar satu unit C320 bisa benar-benar diuji

1. Dapatkan akses pemilik yang disetujui, verifikasi unit fisik DEV-01
   dari konsol atau jalur manajemen yang independen dan tepercaya.
   Catat jenis chassis, HW revision, semua kartu kontrol/PON/uplink
   dan running firmware/build masing-masing, tanpa menyimpan raw
   serial, alamat management atau secret di Git/chat.
2. Validasi jalur SSH ber-host-key tepercaya dan akun khusus
   read-only jika tersedia; jika tidak, evaluasi SNMPv3 atau vendor
   channel yang BENAR-BENAR tersedia pada firmware aktual.
   Jangan membuka Telnet/SNMPv2/FTP ke internet demi uji.
3. Hanya setelah dokumentasi cocok firmware aktual, jalankan
   perintah baca yang telah diverifikasi. Redaksi identitas pribadi
   dan rahasiakan raw output. Output yang formatnya berbeda
   harus fail closed, bukan menebak kompatibilitas.
4. Beri label evidence physical hanya setelah tes nyata
   tenant/device binding, review dan negasi akses lulus.

## Gerbang terpisah sebelum update firmware OLT

ZTE memiliki dokumentasi produk C320 resmi, dan referensi
maintenance/upgrade lama menggarisbawahi backup, status kartu,
alarm, urutan sesuai rilis dan uji pasca-upgrade. Referensi lama
B U K A N otorisasi memilih firmware untuk perangkat 2026.
Perlu release notes resmi yang sesuai exact firmware dan kartu
yang terpasang, paket vendor resmi beserta checksum yang
diverifikasi independen; uji restore backup, status alarm
sehat, penilaian dampak pelanggan, maintenance window
disetujui, maker-checker independen, operator konsol fisik
dan rollback teruji. Setiap kekurangan berarti BLOCKED.
Walaupun semua bukti terpenuhi, versi R7.1 tetap HUMAN_REVIEW
ONLY dan tidak dapat melakukan upgrade karena belum ada
aktuator firmware atau pengujian keselamatan dengan OLT.

Referensi publik yang harus dicocokkan dengan rilis aktual:
https://support.zte.com.cn/support/docmap/00000455/en/operation.html
Dokumen ZXA10 C300/C320 Command Reference dan C320 Maintenance
Manual hanyalah pembanding awal, bukan sertifikasi satu unit.

## Keputusan proyek

ADR-001/002/012 tetap berlaku; FR-016 maju hanya untuk parser
offline, TC-OLT-01 dan FR-017 write tetap NOT RUN/BLOCKED.
Tidak ada perubahan firewall penyedia, jaringan customer,
K3s, PostgreSQL dan firmware unit fisik pada milestone ini.

## Bukti fitur R7.1 setelah review independen

[PR #71](https://github.com/mr-ipat/ipat/pull/71) MERGED at exact original code SHA d452d1be6943bb4b3685b2136ad30b587e6af1e9. Actual independent four-job feature PR GitHub CI 36249894205 and new feature-main CI 36250108104 both SUCCESS. The nonprivileged actual Ubuntu 26.04.1 VPS canonical SOURCE passed 145 locked offline Rust tests, five real offline Rust-CLI synthetic file/permission tests, five big-red PRD/firmware-no-execution contracts and seven previous R6.8 dashboard static tests; unrelated Node DOM existing test ran independently on authorized Mac (Node v22.22). No OLT management network packets were sent.

Owner Mac and VPS Git checkouts matched GitHub main at feature SHA. Existing private preview was safely restarted only through the owner Mac SSH tunnel; REAL HTTP GET 200/no-store for HTML, CSS and JS proved the prominently sized BRIGHT RED PRD warning is visible on all three role-selectable previews; all platform, tenant and operations APIs continued to deny unauthenticated GET HTTP401. FileVault encrypted source backup Restic snapshot 63c7c461 was isolated SHA256 restored and all packs read; selected historical root-readable configuration independently restored, NOT entire VPS or production database PITR. Live VPS K3s/PostgreSQL/nftables remain inactive. Clean-main readiness 8/8 automatic PASS but 7/7 independent external safety gates BLOCKED, commercial NO_GO.

Missing physical test inputs and owner approvals remain unchanged. A real authorized C320 first-read is tracked in [Issue #72](https://github.com/mr-ipat/ipat/issues/72); proposed firmware upgrade with its own high-risk approval/backup/rollback is tracked in [Issue #73](https://github.com/mr-ipat/ipat/issues/73). Success of parsing synthetic text and manual flags never changes the OLT status from UNTESTED to VALIDATED, and neither issue means firmware execution was scheduled.


## R7.4 — Audit dashboard PRD dan klaim laboratorium

**PERINGATAN BESAR MERAH: PLATFORM ADMIN, TENANT ADMIN DAN NOC
MASIH PRATINJAU, BUKAN DASHBOARD SESUAI PRD SECARA END-TO-END.**
Masing-masing kini menampilkan gap FR terpisah pada kotak merah
di bawah release gates, bukan hanya satu peringatan global.
Semua implementasi role demo tetap lokal/browser tanpa login.
C320 khusus pengujian menurut operator, namun TC-OLT-01
tetap tidak berjalan. Packet readiness offline tidak bisa
mengubah status fisik, membuka koneksi atau mengizinkan firmware.
PRD tetap dipertahankan; gap aktual terperinci pada
[DASHBOARD_PRD_AUDIT_R74.md](DASHBOARD_PRD_AUDIT_R74.md) serta
[C320_ISOLATED_LAB_R74.md](C320_ISOLATED_LAB_R74.md).


## R7.5 product-owner approved scheduling, not PRD completion

Subdomain/custom domain verification and inter-DOMAIN session isolation
(FR-004/AC-09) explicitly DEFERRED to M2 following private integrated
lab (ADR-020). No requirement removed. **LARGE RED GAP REMAINS** in
all three real-user dashboards: no OIDC/MFA+verified membership/POP,
server-controlled menu, real cross-tenant backend/RLS tests or live
device data. Shared private localhost URL never proves tenant
isolation. Device TC-OLT-01 NOT RUN, firmware still HARD-DISABLED.
