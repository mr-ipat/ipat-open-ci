# R7.2 — Pemeriksaan integritas berkas firmware C320 lokal, BUKAN upgrade

**Tanggal:** 26 September 2026, Asia/Jakarta
**Pengembang:** Mr. iPat
**Cakupan:** persiapan keselamatan DEV-01, bukan integrasi fisik atau upgrade.

## PERINGATAN PRD — BELUM TERPENUHI

**TIDAK ADA OLT ZTE C320 yang terhubung ke IPAT.**
Tes TC-OLT-01 (inventory fisik) belum berjalan dan
upgrade firmware fisik sama sekali **TIDAK dilakukan**.
Kondisi ini ditampilkan sebagai banner MERAH BESAR di
seluruh tiga pratinjau dashboard dan daftar
[gap PRD yang terbuka](PRD_DEVIATIONS_R71.md).

PRD FR-016 mengizinkan simulasi awal jika fisik belum tersedia.
Firmware upgrade adalah permintaan tambahan berisiko tinggi;
tidak ada otorisasi firmware otomatis dari keberhasilan tes simulator.

## Fitur yang baru diselesaikan di sumber ini

`deploy/scripts/lab/r72/c320-firmware-check.py` adalah pemeriksa
SHA-256 **100% offline** untuk satu berkas dengan nama tetap
`image.bin` pada folder privat operator. Ia **tidak memiliki**
SSH, SNMP, Telnet, FTP, HTTPS, API, perintah OLT,
fungsi transfer berkas, ataupun actuator firmware.

Pemeriksa hanya dapat dijalankan oleh akun non-root
dengan flag `IPAT_R72_APPROVE_OFFLINE_HASH_ONLY=YES`.
Folder harus absolut, pemilik akun yang sama,
mode 0700, bukan symlink. Berkas
`plan.json`, `vendor.sha256`, `image.bin`
harus mode 0600, bukan symlink/hardlink, memiliki
pemilik yang sama dan masing-masing berukuran
wajar (metadata maksimum 8 KiB, file 1 GiB).
File dibuka menggunakan `O_NOFOLLOW` dan identitas
inode diperiksa. Nama dan field JSON harus
cocok dengan target ZTE C320 dan tidak boleh
mengandung traversal maupun field tambahan.

Contoh format **metadata hanya untuk menguji
kontrak file** — BUKAN informasi firmware nyata:

```json
{
  "target_id": "DEV-01",
  "vendor": "ZTE",
  "model": "ZXA10 C320",
  "card_type": "SYNTHETIC",
  "image_kind": "software",
  "target_version": "SYNTHETIC-ONLY",
  "release_reference": "SYNTHETIC-NOT-VENDOR"
}
```

`vendor.sha256` harus berupa
`64-karakter-heksadesimal` diikuti dua spasi
dan `image.bin`. **Checksum itu merupakan
klaim yang dipindahkan operator**, bukan
bukti bahwa berkas berasal dari ZTE atau
cocok dengan kartu OLT tertentu.
Untuk bukti autentisitas harus ada
verifikasi independen terhadap portal
vendor resmi, hak lisensi untuk image,
release notes rilis tepat dan daftar
kartu yang kompatibel serta
tanda tangan/manifest tepercaya apabila
vendor menyediakan. Jangan unggah
firmware proprietary ke Git atau chat.

Hasil sukses hanya mengembalikan
`local_sha256_equals_operator_supplied_checksum=true`
dan secara eksplisit selalu memberi
`vendor_release_authenticity_independently_proven=false`,
`actual_c320_board_compatibility_verified=false`,
`physical_recovery_and_approvals_verified=false`
dan `firmware_upgrade_enabled=false`.
Tidak ada flag yang dapat mengaktifkan
firmware write, bahkan setelah checksum cocok.

## Pengujian berulang

Tes baru menggunakan **byte sintetis bukan
firmware ZTE** yang dibuat dalam folder
sementara oleh `unittest`.
Pengujian wajib mencakup: SHA-256 benar,
image berubah, checksum salah, path
traversal, metadata ekstra, model salah,
symlink/hardlink, mode berkas 0644,
direktori 0755, tanpa consent, dan
ketiadaan API/perintah remote upgrade.

```bash
python3 -m unittest discover \
  deploy/scripts/lab/r72 -p test_c320_firmware_hash.py -v
python3 deploy/scripts/lab/r72/c320-firmware-check.py --requirements
```

Kode dapat dievaluasi dari komputer pengembang.
**Jangan** menggantinya dengan perintah
upgrade C320 dari manual versi lain.

## Gerbang integrasi fisik dan firmware terpisah

Langkah fisik selanjutnya: operator yang
memiliki konsol OLT tepercaya dan izin
harus memverifikasi unit DEV-01,
seluruh papan kontrol/PON/uplink, hardware
revision, running boot/software/firmware
dan jalur baca-saja manajemen asli.
Output CLI rahasia tetap dalam folder
operator privat; verifikasi offline R7.1
hanya melaporkan sintaks dan jumlah baris,
bukan bukti fisik otomatis.

Firmware upgrade memerlukan **semua**
dari: hasil identifikasi fisik, dokumen
kompatibilitas rilis exact dari vendor,
SHA-256+autentisitas, backup konfigurasi
dan kemampuan restore teruji, pengecekan
alarm, baseline ONU dan perkiraan
dampak pelanggan, maintenance window
disetujui, dua manusia pembuat/penyetuju
berbeda, konsol fisik independen
dan rollback yang diuji. Barulah desain
aktuator boleh ditinjau melalui proses
perubahan tersendiri dan pilot yang
tidak mengganggu pelanggan. Jangan
menganggap semua boolean manual
sebagai bukti observasi.

Keterbatasan referensi vendor: panduan
pemeliharaan C320 terdahulu
membicarakan inventaris kartu,
backup dan urutan spesifik per rilis;
itu hanya konteks risiko, bukan
instruksi valid untuk unit firmware
yang belum diidentifikasi pada 2026.
Rujukan awal peta dokumen vendor:
https://support.zte.com.cn/support/docmap/00000455/en/operation.html

**Status akhir produk:** untested OLT fisik;
firmware disabled, ACS fisik dan
semua dashboard pelanggan nyata
belum siap. Production NO_GO.
Batas pekerjaan fisik ada di Issue #72;
gerbang firmware berisiko tinggi
di Issue #73.
