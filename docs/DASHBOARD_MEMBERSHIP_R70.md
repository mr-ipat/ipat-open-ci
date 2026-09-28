# R7.0 — Skema kandidat keanggotaan dashboard, PostgreSQL sintetis

**Developer:** Mr. iPat
**Status:** Kandidat laboratorium, **BUKAN** database identitas produksi, login atau hak akses langsung.
**Tanggal:** 26 September 2026, Asia/Jakarta.

## Tujuan

Mengembangkan fondasi berikutnya setelah pratinjau tiga dashboard
R6.8 dan verifikasi token RS256 R6.9. Tanda tangan JWT yang sah
sendiri **tidak** membuktikan bahwa pengguna merupakan anggota
perusahaan atau memiliki hak NOC/POP. Skema ini memisahkan
catatan keanggotaan yang harus disetujui operator
dari klaim role/tenant yang dapat dipalsukan di token atau header.

Implementasi `deploy/db/migrations/0003_lab_identity_memberships.sql`
adalah **migration candidate untuk PostgreSQL 16 CI sekali pakai**,
belum keputusan final ADR-005 mengenai shared-schema vs
tenant-isolated DB dan belum menyentuh VPS asli.

## Cakupan MUST — lab ini

- `ipat_platform.identity_memberships` mengikat
  `tenant_id`, `issuer` dan `subject` yang
  ditetapkan operator ke salah satu role yang dibatasi
  (`tenant_admin`, `noc_engineer`, `helpdesk`,
  `auditor`). Ada `approved_by`, expiry dan revocation;
  keanggotaan dua tenant tidak dapat dianggap identik
  hanya karena nama pengguna atau JWT `sub` sama.
- `ipat_platform.identity_pop_grants` berelasi
  dengan gabungan tenant+issuer+subject+role yang tepat,
  sehingga pemberian POP perusahaan A tidak sah
  untuk role atau perusahaan B.
- `ipat_platform.platform_principals` terpisah
  dari keanggotaan tenant. `platform_owner` tidak
  otomatis menjadi anggota setiap perusahaan
  dan tidak memiliki hak membaca device secret.
- Ketiga tabel memiliki PostgreSQL RLS
  **ENABLE + FORCE** tanpa policy runtime,
  tanpa izin baca/tulis kepada role
  `ipat_app_runtime`, tanpa SECURITY DEFINER
  enrollment shortcut. Runtime API dan dashboard
  bisnis yang ada tetap HTTP 401.
- Tes negatif di PostgreSQL disposable menguji
  bahwa runtime tidak dapat SELECT/DELETE/TRUNCATE
  entri identitas; tabel tetap tanpa izin SELECT/
  INSERT/UPDATE/DELETE untuk role runtime;
  FK gabungan menolak role/POP salah, domain
  platform dan tenant tidak bercampur,
  serta kondisi revocation/expiry struktural benar.

**Batas penting:** tes seeding menggunakan superuser
synthetic pada database ephemeral CI, bukan sumber
otorisasi yang akan digunakan oleh runtime.
SQL `approved_by` dan expiry saja tidak
membuktikan autentikasi approver, kekuatan MFA,
pencabutan tepat waktu, maupun keanggotaan nyata.
Tanpa perantara tepercaya, siapa pun yang bisa
mengirim `sub` palsu ke query lookup akan berisiko;
**karena itu belum ada endpoint lookup/API atau
GRANT**. Binding dinamis harus dilakukan
dari hasil verifikasi OIDC nyata dan database
dengan transaksi server-side yang dibatasi.

## Cara menguji

Lakukan hanya pada CI PostgreSQL ephemeral yang
secara independen sudah menuntaskan migrasi
`0001_lab_tenant_rls.sql`, seeding dua tenant
sintetis dan `0002_lab_job_outbox.sql`.
Jangan jalankan terhadap server VPS pelanggan:

```bash
# Prasyarat lingkungan HANYA dalam disposable GitHub Actions job
python3 -m unittest discover deploy/db/tests \
  -p 'test_postgres_rls_integration.py' -v
python3 -m unittest discover deploy/db/tests \
  -p 'test_job_outbox_integration.py' -v
python3 -m unittest discover deploy/db/tests \
  -p 'test_identity_memberships_integration.py' -v
```

GitHub menjalankan job yang sama dengan
PostgreSQL 16.9 satu kali pakai dan secret sintetis.
Pengujian lama logical/physical recovery
**tidak** dihitung sebagai backup skema identitas
maupun bukti pemulihan identitas produksi.

## Roadmap dashboard bersyarat

| Fase | Perkiraan perencanaan sejak 26 Sept 2026 | Bukti keluar |
|---|---|---|
| Tiga rancangan UI | Sudah pada R6.8 | Preview tiga workspace privat, data sintetis |
| Login OIDC/MFA + akses lab | 1–2 minggu, 3–10 Okt | Provider asli, login/logout, verified membership/POP, menu dan API deny lintas tenant |
| Administrasi/tenant/NOC data terintegrasi | 4–6 minggu, 24 Okt–7 Nov | Domain sah, metadata tenant, inventory/subscriber/POP, telemetry awal, audit, RLS end-to-end |
| Pilot ISP dengan perangkat sesungguhnya | 8–12 minggu, 21 Nov–19 Des | Sekurangnya satu ONT exact firmware, CWMP asli terautentikasi, peran nyata, operasi pengawasan, failover dan backup diuji |

Tanggal adalah **estimasi jika pekerjaan diteruskan dan
persyaratan terpenuhi**, bukan klaim pekerjaan berlangsung
secara asinkron, bukan janji rilis, dan bukan
sertifikasi operasional/komersial. Hambatan:
pemilihan/operasi IdP OIDC, kepemilikan domain
perusahaan, persetujuan role matrix/ADR,
identitas perangkat, pemulihan menyeluruh
serta tujuh gate eksternal produksi yang
masih terblokir.

## Berikutnya, MUST

1. Sediakan Keycloak/IdP tepercaya terisolasi dan
   uji OIDC discovery, JWKS rotation, Authorization
   Code+PKCE, cookies host-only, CSRF, logout dan MFA.
2. Hubungkan `VerifiedSubject` (issuer yang dipin dan
   token yang sudah diverifikasi) dengan keanggotaan
   dan izin POP dari trusted database, tanpa
   mengambil role dari browser atau JWT custom claims.
   Tentukan actor operator pendaftaran secara
   independen, MFA dan audit dual control.
3. Pastikan backend melakukan evaluasi
   `authz-core` atas pengguna, tenant dan
   perangkat/POP; menu yang tidak berhak
   tidak dikirim, endpoint dan PostgreSQL
   RLS tetap menolak lewat URL/IDOR
   meskipun frontend dimanipulasi.
4. Setelah tes dua tenant dan tiga persona
   bersama DB sintetik lulus, baru boleh
   menyalurkan inventaris pelanggan yang
   telah diotorisasi dan data dari
   ACS/USP yang diuji fisik.

**Keputusan produksi: NO_GO.** Tidak membuka
firewall, tidak menginstal database/K3s pada
VPS yang masih memiliki gate keselamatan
eksternal terblokir.
