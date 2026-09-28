# IPAT R6.7 — pembuktian TLS 1.3 mTLS asli pada gateway ACS Rust

**Developer:** Mr. iPat
**Status fitur:** MUST — *lab selesai diuji*; **belum siap ACS produksi atau ONT nyata**.
**Rujukan implementasi:** rustls 0.23.45, axum-server 0.7.3
dan rustls-pemfile 2.2.0, dikunci dalam Cargo.lock.
Dokumentasi resmi:
<https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html>
dan <https://docs.rs/axum-server/latest/axum_server/tls_rustls/>.

## Mengapa milestone ini diperlukan

R6.6 menghasilkan RPC baca dan pengelolaan sesi CWMP sintetis
tetapi belum pernah membuktikan autentikasi perangkat pada
sambungan jaringan. R6.7 menambahkan **proses Rust tersendiri**
dengan TLS 1.3 asli yang mewajibkan sertifikat klien ditandatangani
CA laboratorium tepercaya. Proses ini **hanya** menguji
autentikasi transport dan parser; tidak menganggap sertifikat
yang dipercaya otomatis membuktikan identitas perangkat,
kepemilikan tenant, atau izin melakukan provisioning.

## Sudah diimplementasikan — MUST laboratorium

- `apps/cwmp-gateway/src/bin/cwmp-mtls-lab.rs`: server TLS 1.3
  Rust asli memakai `WebPkiClientVerifier` tanpa opsi
  anonim, tanpa mode bypass sertifikat, dan hanya
  `127.0.0.1:3433` (literal, tidak dapat diganti
  melalui parameter). Tidak ada public ingress.
- Tanpa `IPAT_RUN_PRIVATE_CWMP_MTLS_LAB=YES`, proses
  keluar dengan kode 4, sebelum membuka listener.
  Proses menolak berjalan sebagai root.
- Operator harus memberikan **tiga berkas lokal**
  di luar repositori: CA sertifikat klien yang
  tepercaya, sertifikat server dan private key
  server. Path absolut, parent direktori 0700
  milik akun yang menjalankan aplikasi; masing-masing
  berkas harus 0600, tanpa symlink, bukan hardlink,
  ukuran maksimum 32 KiB. File dibuka dengan
  `O_NOFOLLOW` dan diperiksa kembali setelah
  terbuka. Server tidak mencetak isi sertifikat,
  private key maupun body perangkat.
- Rustls memvalidasi rantai sertifikat klien,
  masa berlaku dan tujuan `clientAuth` terhadap
  CA lokal yang disediakan. Proses mengiklankan
  HTTP/1.1, TLS 1.3 saja dan menonaktifkan
  TLS early data. Ini tidak termasuk kebijakan
  pencabutan sertifikat (CRL/OCSP) produksi.
- `POST /lab/mtls/parse-inform` dapat dicapai
  hanya setelah mTLS berhasil, lalu memvalidasi
  SOAP Inform terbatas. Respons JSON tidak
  mengembalikan serial atau data sensitif.
  JSON boleh menyatakan
  `mtls_certificate_chain_verified=true`
  sebagai hasil verifikasi TLS **transport saja**,
  sedangkan `tenant_bound=false`,
  `device_enrolled=false`,
  `cwmp_response_sent=false`,
  `production_acs=false` tetap eksplisit.
- **`/cwmp` selalu HTTP 503**, sekalipun
  klien mengirimkan sertifikat CA yang benar,
  atau header `X-Tenant-Id` dan
  `X-Client-Cert-Verified` palsu. Kode belum
  bisa membuat `AuthenticatedPeer` milik
  `cwmp-admission`, tidak mengonsumsi antrean
  pekerjaan dan tidak menulis database.

## Uji wajib dan reproduksi — MUST laboratorium

`deploy/scripts/lab/r67/mtls-loopback-contract.sh`
hanya boleh dijalankan di lingkungan pengujian
Ubuntu 26.04 yang terisolasi, bukan pada layanan
publik. Skrip memakai `umask 077`, membuat
CA/server/client test EC P-256 sementara dalam
direktori `/tmp` mode 0700, serta membuat
CA lain yang tidak dipercaya. Setelah pengujian
skrip mematikan **hanya** proses yang dibuatnya
dan menghapus seluruh sertifikat dan private key
laboratorium dari folder sementara.

Kasus uji end-to-end dengan OpenSSL dan cURL:
sertifikat klien benar berhasil melewati mTLS;
tanpa sertifikat klien ditolak; CA klien
tidak dipercaya ditolak; sertifikat serverAuth
yang dipakai sebagai klien ditolak; nama DNS
server salah ditolak; CA server salah ditolak;
symlink/private key terbuka ditolak; SOAP Inform
sintetis yang valid dapat diparse tanpa enrollment;
SOAP XML dengan DTD ditolak; HTTP `/cwmp` tetap
503; hanya localhost listen dan listener
benar-benar hilang setelah pengujian.

```bash
cargo fmt --all -- --check
cargo test --workspace --locked --offline
cargo build --locked --offline -p cwmp-gateway --bin cwmp-mtls-lab
python3 -m unittest discover deploy/scripts/lab/r67 -p test_r67_review.py -v
IPAT_R67_RUN_SYNTHETIC_MTLS_TEST=YES \
  bash deploy/scripts/lab/r67/mtls-loopback-contract.sh
```

Semua uji dinamis hanya memakai sertifikat sintetis
yang dihasilkan saat pengujian. **Jangan** memasukkan
kredensial asli router, ONT, tenant atau sertifikat
produksi ke contoh maupun repositori.

## Yang belum ada — MUST sebelum ONT dan pelanggan

- Binding kriptografis **identitas setiap klien**
  ke sertifikat/SPKI tertentu, enrollment
  independen yang disetujui operator, tenant
  terotentikasi dan pemeriksaan izin (bukan
  hanya CA yang sama). Komponen mTLS dan
  `cwmp-admission` saat ini **belum tersambung**.
  Tidak boleh menggunakan header yang
  dapat dibuat sendiri oleh klien sebagai
  bukti kriptografis maupun tenant.
- Kebijakan CA/sertifikat nyata, rotasi
  kunci dan pencabutan CRL/OCSP,
  penanganan jam yang meleset, pembatasan
  koneksi, observability tanpa kebocoran
  identitas, dan audit enrollment.
- HTTP CWMP yang benar dengan
  `InformResponse`, CPE empty POST,
  RPC ACS sebagai HTTP response, hasil
  `GetParameterValues` berikutnya,
  fault/timeouts dan pemulihan sesi di
  database tenant melalui
  otorisasi RBAC+ABAC deny-default.
- Perangkat laboratorium ONT VSOL/ZTE
  dengan model/firmware sebenarnya,
  sertifikat terpercaya, backup,
  izin uji, dan pengukuran lulus/gagal
  per kombinasi. Tidak ada klaim
  kompatibilitas fisik dari uji ini.

**SHOULD:** simulator ONT TLS dengan sertifikat
perangkat terdaftar, CA berbeda antar tenant
jika diperlukan, dan pengukuran handshake
latency, koneksi bersamaan serta audit
deny tanpa bocor.

**LATER:** penyediaan profil vendor secara
massal, upgrade firmware dan konfigurasi
berisiko tinggi membutuhkan mekanisme
persetujuan, audit serta rollback terpisah.

## Ancaman dan pembatasan produksi

CA tunggal yang menerima sertifikat klien
apa pun dari CA itu **bukan** otorisasi
kepemilikan perangkat atau tenant. Karena
itu server R6.7 sama sekali tidak memberi
akses ACS atau fungsi read/write riil.
Penggunaan TLS 1.3 di laboratorium belum
membuktikan kompatibilitas ONT lama atau
dukungan standar CWMP dari perangkat
VSOL/ZTE. Realitas perangkat dan rute
pelanggan tetap menunggu pengujian yang
sah serta aman.

Tidak ada perubahan firewall penyedia,
port publik, konfigurasi router pelanggan,
K3s, PostgreSQL langsung maupun layanan
VPS produksi. Native USP Controller tetap
terpisah dan wajib dikembangkan sesuai
ADR-002.

## Bukti setelah penggabungan fitur asli

PR [#63](https://github.com/mr-ipat/ipat/pull/63) telah digabungkan pada commit `2baaf8419b3eba6933854847db73a7120612c579`. CI independen pada PR (`36239520353`) dan pada main sesudah merge (`36239646430`) sama-sama SUCCESS di seluruh empat job, mencakup pengujian Rust/mTLS, K3s disposable Ubuntu 26.04 serta dua jalur pemulihan PostgreSQL sintetis yang terpisah. Pada checkout canonical source Ubuntu 26.04.1 VPS yang **tidak diinstal sebagai layanan live**, 123/123 tes Rust terkunci/offline lulus, enam tes static-kontrak lulus dan uji TLS1.3 OpenSSL/cURL sungguhan kembali lulus tanpa listener tersisa. Checkout dan commit Mac FileVault serta GitHub sama. Backup sumber terenkripsi exact source Restic `884cc492` berhasil diuji restore SHA256 dan seluruh encrypted pack; selected historical root-readable configuration juga diuji pemulihan terpisah, bukan pemulihan seluruh VPS atau PITR PostgreSQL. Semua layanan VPS K3s/PostgreSQL/nftables masih inactive, tidak ada pelanggan atau ONT fisik yang diakses. Gate readiness otomatis 8/8 lulus pada Git branch main yang bersih, tetapi **7/7 verifikasi eksternal independen masih BLOCKED**, keputusan produksi **NO_GO**.

[Status penggunaan produk dan kriteria pilot](PRODUCT_READINESS_R67.md). Bukti sumber/dokumen SHA terakhir akan direkam melalui komentar PR immutable setelah checkpoint dokumentasi digabung.
