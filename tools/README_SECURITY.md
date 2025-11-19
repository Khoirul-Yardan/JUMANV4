# JuMan — Laporan Keamanan & Rekomendasi

> Dokumen ini dapat dibuat otomatis oleh `tools/generate_security_readme.py`.

## Ikhtisar
JuMan menyimpan dokumen terenkripsi di folder `storage` dan membuat backup terenkripsi (`*.jumanbackup`). Keamanan bergantung pada perlindungan *master key* yang digunakan untuk mengenkripsi file dan backup.

Dokumen ini menjelaskan:
- Mekanisme enkripsi saat ini
- Vektor serangan yang relevan
- Mitigasi dan rekomendasi praktis
- File yang harus dilindungi dan di mana menyimpannya
- Tindakan migrasi dan pengujian

---

## Ringkasan temuan (otomatis)

Data dir: C:\Users\yarda\Documents\JuMan
Exists: True
config.json: FOUND
config.properties: MISSING
master.key: MISSING
master.key.enc: FOUND
recovery.txt: FOUND
Storage exists: True
Backups: None

---

## 1) Mekanisme enkripsi saat ini
- Algoritma: AES-GCM (IV 12 byte, tag 128 bit) digunakan untuk enkripsi file dan zip backup.
- Backup: ZIP kemudian dienkripsi (AES-GCM).
- Master key (sebelum perbaikan): `master.key` disimpan sebagai Base64 tanpa proteksi.
- Perbaikan yang ditambahkan (tools Python): `master.key.enc` dapat menyimpan master key terenkripsi oleh kunci yang diturunkan dari password (PBKDF2). Skrip: `tools/juman_secure.py`.

## 2) Vektor serangan (Attack)
Berikut vektor yang perlu diperhatikan:

- Akses filesystem (Local file access): jika attacker mendapatkan akses file (mis. malware atau akses fisik), file seperti `master.key` atau `master.key.enc` bisa dicuri. Jika master key dicuri, semua file terenkripsi dapat didekripsi.
- Backup leakage: jika backup berisi `master.key` atau tidak dienkripsi dengan baik, pencuri backup akan mendapatkan data sensitif.
- Weak admin password: password lemah mempermudah serangan kamus/brute-force untuk membuka `master.key.enc` atau akun admin.
- Rename/extension manipulation: aplikasi sebelumnya mengandalkan ekstensi `.jmn` — rename menyebabkan kegagalan fungsional. (Telah diperbaiki pada `FileManager` yang mencari file tolerant.)
- SSD/Filesystems: secure delete dengan overwrite tidak selalu efektif pada SSD/volume dengan snapshot/backup, sehingga data mungkin dapat dipulihkan.
- Network risks: jika fitur sinkronisasi/remote ditambahkan tanpa TLS atau validasi, data dapat disadap.

## 3) Mitigasi penting (Defence)
Prioritas tinggi ( segera ):

1. **Enkripsi master key**: simpan `master.key` hanya dalam bentuk terenkripsi (`master.key.enc`) menggunakan kunci turunan dari password kuat (gunakan PBKDF2/scrypt/Argon2). Jangan simpan master key plain.

2. **Jangan sertakan master key dalam backup**: backup hanya berisi `storage/` dan file konfigurasi non-sensitif. Jika ingin backup master key, enkripsi dengan password berbeda dan simpan terpisah (mis. offline secure vault).

3. **Tingkatkan KDF**: gunakan Argon2 atau set PBKDF2 iterasi tinggi (>=200.000) menyesuaikan performa.

4. **Proteksi hak akses**: set permission file `master.key.enc` ke user saja (Windows ACL atau POSIX `chmod 600`). Batasi akses folder `JuMan`.

5. **Verifikasi integritas backup**: tambah HMAC atau digital signature pada backup sehingga restore menolak file yang telah diubah.

6. **Audit & Logging**: catat pembuatan/restore backup, perubahan user, dan percobaan login gagal.

Menengah:
- Gunakan OS keystore (DPAPI / Keychain / NSS DB) bila memungkinkan.
- Sediakan flow reset password yang aman (recovery token terenskripsi dan disimpan terpisah).
- Tambahkan metadata dan magic header pada file terenkripsi agar tidak bergantung pada ekstensi.

Long-term:
- Hardware-backed keys (TPM/secure enclave) untuk kunci master.
- HSM / remote key management untuk deployment kritikal.

## 4) Files yang harus disimpan aman
Simpan dengan sangat aman dan perlakukan sebagai sensitive:

- `master.key` / `master.key.enc` — kunci master (paling sensitif)
- `recovery.txt` — token pemulihan (jika ada)
- Backup files (`*.jumanbackup` atau zip) — backup terenkripsi
- `config.properties`/`config.json` — berisi salt/hash password (sensitif)

Tempat penyimpanan yang direkomendasikan:
- Offline hardware keystore (USB token) atau password manager yang aman.
- Jika di-disk, taruh di directory dengan ACL terbatas (user app saja), dan enkripsi file.

## 5) Rekomendasi praktis & contoh perintah (PowerShell)
- Set ACL (Windows): batasi akses file master key:

```powershell
$mk = "$env:USERPROFILE\Documents\JuMan\master.key.enc"
# hanya owner dan admin
icacls $mk /inheritance:r
icacls $mk /grant:r "$env:USERNAME:(R,W)"
icacls $mk /grant:r "Administrators:(R)"
```

- Ubah mode di Linux (jika digunakan):

```bash
chmod 600 ~/Documents/JuMan/master.key.enc
chown $USER:$USER ~/Documents/JuMan/master.key.enc
```

- Hapus file sensitif dari backup: pastikan BackupService mengecualikan `master.key`.

## 6) Rencana migrasi (contoh langkah)
1. Buat backup offline dari data saat ini.
2. Jalankan migrator untuk mengenkripsi `master.key`:
   - Jika `master.key` plain ada: baca, minta password admin baru, enkripsi dan simpan `master.key.enc`, hapus `master.key`.
3. Perbarui aplikasi (Java) agar membaca `master.key.enc` (user diminta masukkan password pada startup).
4. Verifikasi semua fungsi (store/open/backup/restore) di lingkungan testing.

## 7) Pengujian dan validasi (untuk jurnal)
- Tes fungsional: store/open setelah migrasi, backup + restore, dan cek integritas file.
- Tes keamanan: menyalin file `master.key.enc` ke VM lain, coba brute-force terbatas (sampel) untuk menguji parameter KDF.
- Tes forensik: coba recovery setelah secure delete pada HDD vs SSD, dokumentasikan hasil.

## 8) Referensi singkat & snippet implementasi
- Gunakan `AESGCM` dari `cryptography` (Python) atau `javax.crypto` (Java) untuk implementasi AES-GCM.
- Gunakan `PBKDF2HMAC` atau Argon2 (lebih direkomendasikan) untuk derivasi kunci dari password.

---

## Lampiran: temuan detil
```
{
  "data_dir": "C:\\Users\\yarda\\Documents\\JuMan",
  "exists": true,
  "files": {
    "config.json": true,
    "config.properties": false,
    "master.key": false,
    "master.key.enc": true,
    "recovery.txt": true
  },
  "storage_exists": true,
  "backups": []
}
```

---

Dokumen ini dapat digenerate otomatis menggunakan `tools/generate_security_readme.py`. Untuk migrasi otomatis dan pengetesan, gunakan skrip-skrip di folder `tools/`.
