# IPAT — Status Kesiapan Produk R6.7

**Pemilik pengembangan:** Mr. iPat
**Tanggal:** 2026-09-26 (Asia/Jakarta)
**Keputusan untuk pelanggan riil:** **NO_GO**.
**Yang boleh dipakai sekarang:** laboratorium privat menggunakan
data dan sertifikat sintetis, bukan sistem operasional perusahaan ISP.

Dokumen ini membedakan *fitur kode yang lulus tes*,
*layanan yang sudah berjalan pada lingkungan terisolasi*,
dan *kelayakan komersial yang mensyaratkan uji perangkat fisik*.

| Komponen | Bukti yang tersedia | Batas penggunaan |
|---|---|---|
| Dashboard kontrol privat | Halaman demonstrasi melalui SSH tunnel milik operator Mac | Bukan dashboard perusahaan terautentikasi, tidak terhubung ke ONT |
| Original ACS Rust | Inform/InformResponse dan satu `GetParameterValues` hanya simulator offline | Belum gateway `/cwmp` autentik untuk perangkat sungguhan |
| TLS gerbang ACS | R6.7 mTLS TLS 1.3 kriptografis **asli** dengan CA dan sertifikat sementara | Listener hanya `127.0.0.1:3433`; `/cwmp` selalu HTTP 503 |
| Tenant/RBAC/RLS | Policy Rust dan PostgreSQL tenant-RLS/job diuji dengan data sintetis | OIDC, role dan runtime database ACS nyata belum terintegrasi |
| Native USP Controller | Proses terpisah dengan health/synthetic trust module | Belum protobuf USP, MTP aman dan perangkat nyata |
| OLT/ONT/MikroTik | Target matriks dan prosedur aman sudah disiapkan | Belum ada verifikasi interoperabilitas fisik atau onboarding |
| K3s, backup, HA | Pengujian CI Ubuntu 26.04 dan pemulihan terisolasi, backup sumber Restic teruji | Bukan HA produksi, bukan backup seluruh VPS atau PITR database riil |

## Kriteria minimum sebelum pilot perusahaan

1. Transport mTLS yang sudah terbukti harus mengaitkan sertifikat
   klien yang benar dengan **enrollment tiap perangkat**
   yang telah disetujui operator dan **tenant yang sah**.
   Sertifikat dari CA tepercaya saja tidak cukup.
2. Gateway asli melayani sesi CWMP yang benar
   melalui HTTPS dengan InformResponse, empty POST,
   RPC aman sebagai HTTP response, balasan/fault CPE,
   pemulihan timeout, audit dan penyimpanan sesi
   persisten/tenant-scoped yang telah diuji.
3. Autentikasi OIDC, RBAC+ABAC deny-default,
   pemisahan perusahaan, backup dan pemulihan
   database serta secret-management harus diuji
   bersama alur perangkat sebenarnya; menu yang
   tidak sah harus tersembunyi **dan** API menolak.
4. Sekurang-kurangnya satu ONT laboratorium yang
   benar-benar diizinkan dan diketahui model,
   firmware serta identitasnya melakukan Inform
   dan satu operasi parameter yang berhasil,
   termasuk skenario negatif dan bukti aman.
5. Ketujuh gate eksternal keselamatan produksi
   (antara lain jalur rescue independen, pemulihan
   host menyeluruh, perimeter dan desain database)
   tidak boleh lagi berstatus terblokir.
   Jangan mengaktifkan K3s/PG/firewall produksi
   untuk melewati gate ini.

## Bukti pengujian milestone

Pada checkout terpisah VPS Ubuntu 26.04.1,
`cargo test --workspace --locked --offline`
lulus **123/123** tes Rust dan enam pemeriksaan
kontrak keamanan R6.7. OpenSSL dan cURL
menguji handshake mTLS secara nyata:
klien sah diterima, klien tanpa sertifikat/
CA salah/EKU salah ditolak, CA/nama server
salah ditolak, berkas private key tidak
aman ditolak, `/cwmp` masih HTTP 503,
dan listener tes dihentikan setelah selesai.

Perubahan sumber dan dokumentasi masing-masing
harus melalui GitHub CI independen dan
backup sumber terenkripsi. Bukti final
SHA, run CI dan snapshot terpublikasi
secara immutable pada komentar PR
terkait setelah final main diverifikasi
untuk menghindari perubahan SHA berulang.

**Catatan penting:** Hasil laboratorium tidak
berarti kompatibilitas VSOL/ZTE/MikroTik
atau keunggulan terhadap GenieACS.
Project tetap memakai ACS native Rust
serta USP Controller terpisah sesuai
keputusan arsitektur.
