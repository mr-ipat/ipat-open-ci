# R7.4 — Persiapan DEV-01 ZTE C320 laboratorium terisolasi

**Tanggal:** 27 September 2026. Pemilik menyatakan perangkat khusus pengujian, tidak melayani distribusi pelanggan. Ini deklarasi operator, BUKAN bukti model, running firmware, akses, interoperabilitas atau hasil pengujian. DEV-01 dan TC-OLT-01 tetap UNTESTED / NOT RUN.

## Target dan keselamatan

MUST tahap awal: satu ZTE C320, periksa chassis/control/PON/uplink dan running firmware melalui console terpercaya; satu pengujian pembacaan yang sesuai exact firmware. Gunakan jalur privat dan akun khusus read-only, bukti host identity independen, backup konfigurasi privat dan konsol terpisah untuk recovery. Jangan kirim IP manajemen, serial, kata sandi, transkrip penuh atau firmware ke ChatGPT/Git.

Helper baru adalah OFFLINE packet validator. Hasil maksimal HUMAN_REVIEW_REQUIRED meski seluruh pernyataan operator true. Helper tidak membuka koneksi, mengambil kredensial, mendaftarkan perangkat/tenant, menguji firmware atau mengaktifkan akses apa pun.

## Rangkaian uji pertama

1. Melalui konsol independen, operator mencatat seluruh jenis/revisi kartu, exact firmware/build, kanal manajemen tersedia, serta apakah kandidat perintah show card dan show version-running valid pada firmware ini. Perangkat non-live mengurangi dampak pelanggan, tidak menggantikan validasi metode.
2. Buat private directory di luar Git (mode 0700), siapkan R6.0 INPUT.json dengan model/board/firmware yang sudah DIAMATI serta protocol_candidate vendor-cli-readonly. Tool R6.0 menghasilkan DEV-01-staged.json. Salin hasil itu ke folder packet baru sebagai stage.json (0600).
3. Siapkan plan.json (0600) tepat dengan delapan deklarasi boolean di bawah. Mulai semuanya false. Nyatakan true hanya setelah pemeriksaan operator terkait dilakukan. Kedua file harus berada pada satu direktori packet 0700, bukan symlink/hardlink, dan tidak ada file ketiga.
4. Jalankan R74 --requirements dan --check-packet. Jika ada boolean false maka BLOCKED dan laporan menunjukkan prasyarat yang belum diperiksa. Jika semua true hasil HUMAN_REVIEW_REQUIRED, tidak otomatis mengizinkan koneksi.
5. Petugas lab dan reviewer terpisah memeriksa prasyarat, kemudian menggunakan console terotorisasi atau transport yang terpisah sudah tervalidasi untuk mengambil HANYA satu pembacaan. Simpan raw transkrip di storage privat terenkripsi dan redaksi semua identitas sebelum memakai R7.1 offline Rust importer. Jangan gunakan SSH host key hasil scan jaringan yang sama sebagai bukti independen.
6. Bila format aktual berbeda, berhenti; uji parser melalui fixture sintetis/teranonimkan lebih dulu. Setelah review positif/negatif, catat bukti per tuple persis di DEVICE_MATRIX. Jangan promosi berdasarkan tes simulator saja.

## Perintah (semua helper ini OFFLINE)

    cd "$HOME/Projects/ipat-current"
    python3 deploy/scripts/lab/r74/lab-readiness.py --requirements
    python3 deploy/scripts/lab/r60/prepare-device-intake.py \
      --input "$HOME/.local/share/ipat/device-intake/INPUT.json" \
      --output "$HOME/.local/share/ipat/device-intake/DEV-01-staged.json"
    # Owner membuat folder packet lain mode0700, stage.json + plan.json mode0600:
    python3 deploy/scripts/lab/r74/lab-readiness.py \
      --check-packet "$HOME/.local/share/ipat/c320-private-packet"
    # Hanya setelah pembacaan terotorisasi dan bukti disanitasi ke folder privat:
    IPAT_R71_OWNER_CONFIRMS_REDACTED_OFFLINE_CAPTURE=YES \
      cargo run --locked --offline -p olt-core --bin c320-offline-review -- \
      --parse "$HOME/.local/share/ipat/c320-private-cli-evidence"

## plan.json example — semua persetujuan belum ada

    {
      "target_id":"DEV-01",
      "environment":"isolated_lab",
      "protocol":"vendor-cli-readonly",
      "equipment_owner_authorized_lab_read":false,
      "isolated_from_live_subscriber_network":false,
      "dedicated_read_only_account_prepared":false,
      "independent_device_console_available":false,
      "independent_host_identity_verified":false,
      "private_management_route_verified":false,
      "candidate_read_commands_verified_on_exact_device":false,
      "configuration_backup_stored_privately":false
    }

SHOULD setelah pembacaan pertama: per-feature alarm/PON/ONU read-only dan negative tenant/POP checks. LATER, terpisah: firmware upgrade mensyaratkan paket/release note vendor yang cocok tiap card, bukti autentisitas image dan hash independen, tested backup+rollback, alarm/ONU baseline, jadwal, maker-checker terpisah, konsol onsite dan pembatasan dampak. R7.2 hanya offline hash check dan firmware actuator tetap tidak tersedia.

Tes helper tanpa perangkat: python3 -m unittest discover deploy/scripts/lab/r74 -p test_lab_readiness.py -v. Tidak ada perubahan provider firewall, host firewall, K3s atau PostgreSQL live dalam milestone ini.
