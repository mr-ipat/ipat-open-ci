# IPAT R6.9 — Verifikasi kriptografis identitas untuk tiga dashboard

**Developer:** Mr. iPat · **Tanggal:** 26 September 2026
**Status:** milestone **laboratorium terintegrasi**, bukan login SaaS produksi.
**Target:** melanjutkan Platform Admin, Tenant Admin dan NOC R6.8 tanpa memberikan hak akses berdasarkan klaim pengguna yang belum diperiksa.

## Implementasi dan batas kepercayaan

R6.9 menambahkan library `crates/identity-core` menggunakan
`jsonwebtoken 11.1.0` dengan backend kriptografi AWS-LC.
`PinnedIssuer` hanya dibuat dari issuer HTTPS, audience, key ID
dan RSA public key **yang telah dipilih operator melalui jalur
tepercaya**, bukan dari token, header, URL JWKS milik penyerang,
`jku`, `jwk`, `x5u`, atau `x5c`. Tidak ada jaringan ke
identity provider saat memeriksa token.

Verifier menggunakan RS256 saja. Memerlukan signature benar, ID
kunci tepat, issuer, audience tunggal, subject yang valid,
`exp`, `iat`, `nbf`, waktu terbit wajar, leeway maksimum
10 detik, umur token maksimum 900 detik, dan total JWT
maksimum 8 KiB. Algoritma HS256/ketidakcocokan kid, signature
berubah, issuer/audience palsu, token terlalu lama dan key
discovery melalui header ditolak.

Hasil signature yang sah berupa `VerifiedSubject` hanya
memuat subject dan waktu kedaluwarsa, **bukan** keanggotaan
perusahaan, role, POP, MFA atau izin administrator. Klaim
tambahan dari JWT, termasuk `tenant_id`, `roles`, dan
`realm_access`, diabaikan untuk otorisasi.

`apps/control-api/src/oidc_lab.rs` menghubungkan verifier
ke endpoint `GET /lab/auth/verify` hanya jika dashboard
lab benar-benar aktif dan operator secara eksplisit
mengaktifkan `IPAT_LAB_OIDC_VERIFY=YES` pada listener
loopback nonroot. Endpoint memerlukan tepat satu
`Authorization: Bearer` dan mengembalikan hanya:

```json
{
  "jwt_signature_verified": true,
  "tenant_membership_verified": false,
  "business_access_enabled": false,
  "roles_verified": false
}
```

Keluaran tidak mengandung username, serial atau informasi
tenant. Tanpa token/konfigurasi operator yang valid respons
`401`; hanya GET yang diizinkan. Endpoint tidak muncul sama
sekali pada build/router nonlaboratorium atau K3s.
**Seluruh** endpoint bisnis
`/v1/platform/*`, `/v1/tenant/*`,
`/v1/operations/*`, dan perangkat yang
dilindungi **tetap 401** bahkan dengan bearer yang benar.

Issuer dan key berasal dari environment **lokal terkontrol**;
key harus path absolut ke berkas mode 0600 dalam direktori
pemilik mode 0700, tanpa symlink/hardlink, diverifikasi lagi
setelah dibuka dengan `O_NOFOLLOW`. Ini bukan
mekanisme distribusi kunci Keycloak yang sudah diuji.

## Bukti pengujian

- `crates/identity-core/tests/oidc_signature.rs` membuat
  RSA 2048-bit sintetis baru melalui OpenSSL di folder
  sementara. Menguji signature RS256 benar dan pemalsuan
  menggunakan RSA kedua, perubahan signature, HS256
  confusion, kid tidak cocok, issuer/audience/sub/tanggal
  invalid, umur melebihi kebijakan, audience array dan
  pemaksaan `jku`/`x5u`.
- Unit HTTP Axum pada `control-api` memakai JWT RS256
  yang benar namun memverifikasi bahwa klaim role
  administrator/tenant palsu **tidak membuka satu pun API
  bisnis**. Header identitas palsu, bearer tanpa signature,
  serta metode tak diperbolehkan ditolak.
- `deploy/scripts/lab/r69/oidc-private-http-smoke.sh`:
  skrip sekali pakai dengan flag opt-in. GitHub CI pada
  runner sementara menghasilkan RSA/key privat tes dalam
  direktori sementara owner-only, menandatangani JWT dengan
  OpenSSL, mengirim HTTP **nyata** pada literal
  `127.0.0.1:3001`, memastikan token valid hanya
  memvalidasi signature tanpa role/membership, lalu
  menguji GET/POST API platform, tenant, operasional dan
  perangkat masing-masing tetap 401. Menolak konflik
  apabila port 3001 sudah digunakan, tidak menghentikan
  proses bukan miliknya dan menghapus kunci tes.
- `deploy/scripts/lab/r69/test_r69_review.py` memeriksa
  penolakan sumber key dari browser, eksposur endpoint,
  static deny dan kontrak script sebelum tes dinamis.

Untuk checkout disposable yang tidak menjalankan
server lain yang menggunakan port 3001:

```bash
cargo fmt --all -- --check
cargo test --workspace --locked --offline
python3 -m unittest discover deploy/scripts/lab/r69 -p test_r69_review.py -v
cargo build --locked --offline -p control-api
IPAT_R69_RUN_SYNTHETIC_HTTP=YES \
  bash deploy/scripts/lab/r69/oidc-private-http-smoke.sh
```

Jangan menjalankan tes HTTP ini pada host yang sedang
menjalankan preview dashboard. Tes akan menolak konflik.
Jangan gunakan key/token pelanggan asli pada fixture.

## Status tiga dashboard dan jadwal bersyarat

| Ruang kerja | Saat ini | Syarat penggunaan nyata |
|---|---|---|
| Platform Admin | Preview visual privat dan backend menolak tanpa login berotorisasi | Signed OIDC, MFA, role platform dan DB metadata tenant saja |
| Tenant Admin | Preview sintetis dan kebijakan Rust lintas tenant | Keanggotaan yang disetujui, domain diverifikasi, izin delegasi, RLS runtime |
| Operasional NOC | Preview sintetis dan contoh pembatasan POP | User/tenant/POP dari database tepercaya, telemetry dan status perangkat nyata |

Sebagai estimasi perencanaan sejak 26 September 2026:
tampilan ketiganya sudah dapat didemonstrasikan.
Lapisan autentikasi/MFA dan hak akses end-to-end
laboratorium diproyeksikan 1–2 minggu;
integrasi database dan modul operasional dasar
diproyeksikan 4–6 minggu; pilot ISP terintegrasi
dengan perangkat nyata diproyeksikan 8–12 minggu.
Tanggalnya **bersyarat**, bukan komitmen produksi:
ketergantungan pada pilihan IdP, tenant domain,
akses perangkat lab, keberhasilan pemulihan host
dan tujuh gate eksternal yang saat ini masih BLOCKED.

## MUST yang belum selesai

1. Verifikasi asal public key melalui HTTPS OIDC discovery
   dari Keycloak/IdP yang benar, pemilihan audience/issuer
   operasional, rotasi JWKS, pengujian sertifikat, expiry
   dan interoperabilitas token Keycloak asli.
2. Login dan logout OIDC lengkap (Authorization Code+PKCE),
   redirect URI per domain tenant, cookie host-only,
   CSRF/state/nonce, pemeriksaan MFA dan pengelolaan sesi.
   `/lab/auth/verify` **bukan** pengganti login.
3. Tautkan subject terverifikasi ke **membership database
   yang independen**, role platform/tenant dan izin POP,
   lalu jalankan policy Rust di backend dengan PostgreSQL
   RLS dalam satu batas kepercayaan. Menu harus
   disaring server-side dan endpoint tetap menolak
   semua upaya lintas tenant, POP dan role.
4. Pembuktian domain kustom aman, approval/audit tindakan
   berisiko, backup/pemulihan, load/security tests dan
   interoperabilitas ACS/USP perangkat sungguhan.

**Kesimpulan:** milestone ini membuktikan lapisan
identitas JWT bertanda tangan dan batas deny-default
sebelum pengembangan login dan membership nyata,
bukan tiga dashboard operasional siap pelanggan.
Tidak ada perubahan firewall penyedia, listener
publik baru, K3s/PostgreSQL produksi atau CPE.

## Bukti milestone setelah penggabungan fitur R6.9

Implementasi [PR #67](https://github.com/mr-ipat/ipat/pull/67) sudah MERGED sebagai commit `0d5a0298427f816b7e67d1df7ec27f03060fc8f9`. Kedua run GitHub CI independen, PR `36245565621` dan post-feature-main `36245769033`, masing-masing menyelesaikan **empat pekerjaan SUCCESS**: Rust/security/signed JWT HTTP sintetis, cluster K3s Ubuntu26 sekali pakai, serta dua jalur pemulihan PostgreSQL sintetis yang terpisah. Pada source canonical real Ubuntu26.04.1 VPS (bukan penginstalan sebagai layanan), format dan 139/139 tes Rust locked/offline, 5/5 kontrak keamanan, dan pengujian HTTP asli yang menandatangani JWT sintetis dengan OpenSSL semuanya lulus. Port pembuktian identitas khusus `127.0.0.1:3001` berhenti setelah tes tanpa mengubah PID preview dashboard privat yang sudah aktif pada `127.0.0.1:3000`. Tidak ada token, kunci pelanggan, atau tenant riil.

Run pertama yang kemudian digantikan (`36245181998`) gagal pada fixture pengujian karena konflik port 3000/TIME_WAIT serta ekspektasi POST yang keliru terhadap API perangkat yang hanya GET; perbaikan pada **fixture dan pemisahan port laboratorium** diuji sebelum dua CI hijau tersebut. Kesalahan awal itu tidak disembunyikan sebagai pengujian lulus.

FileVault Mac membuat snapshot sumber exact feature terenkripsi Restic `56c893f1`, berhasil di-restore terisolasi dengan hash SHA256 cocok dan semua encrypted pack terbaca. Backup konfigurasi root-readable historis juga berhasil diuji terpisah; **tidak membuktikan pemulihan seluruh VPS atau PITR database sebenarnya**. Tujuh gate keselamatan eksternal serta rilis produksi tetap NO_GO sampai bukti independen terpenuhi.
