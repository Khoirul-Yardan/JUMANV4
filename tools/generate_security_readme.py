#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate_security_readme.py

Simple tool to generate a detailed SECURITY README for JuMan based on current repository/data layout.
It writes `README_SECURITY.md` in the `tools/` folder (overwrites existing).

Usage:
    python generate_security_readme.py --data-dir "<path-to-JuMan-data>" --out tools/README_SECURITY.md

If no data-dir provided, default is the same as JuMan (~/Documents/JuMan).
"""

import argparse
from pathlib import Path
import base64
import json

DEFAULT_DATA_DIR = Path.home() / 'Documents' / 'JuMan'


def inspect_data_dir(data_dir: Path):
    p = Path(data_dir)
    findings = {}
    findings['data_dir'] = str(p)
    findings['exists'] = p.exists()
    findings['files'] = {}
    for name in ['config.json', 'config.properties', 'master.key', 'master.key.enc', 'recovery.txt']:
        findings['files'][name] = (p / name).exists()
    findings['storage_exists'] = (p / 'storage').exists()
    findings['backups'] = [str(x.name) for x in p.glob('*.jumanbackup')] + [str(x.name) for x in p.glob('*.zip')]
    return findings


SECURITY_MD_TEMPLATE = '''# JuMan — Laporan Keamanan & Rekomendasi

> Dokumen ini dibuat otomatis oleh `tools/generate_security_readme.py`.

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

{findings_summary}

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
   - Jika `master.key` plain ada: baca, minta password admin, enkripsi dan simpan `master.key.enc`, hapus `master.key`.
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
{findings_json}
```

---

Dokumen ini dihasilkan otomatis. Untuk migrasi otomatis dan pengetesan, gunakan skrip-skrip di folder `tools/`.
'''


def make_findings_summary(findings):
    lines = []
    lines.append(f"Data dir: {findings['data_dir']}")
    lines.append(f"Exists: {findings['exists']}")
    for k, v in findings['files'].items():
        lines.append(f"{k}: {'FOUND' if v else 'MISSING'}")
    lines.append(f"Storage exists: {findings['storage_exists']}")
    lines.append(f"Backups: {', '.join(findings['backups']) if findings['backups'] else 'None'}")
    return '\n'.join(lines)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--data-dir', default=str(DEFAULT_DATA_DIR))
    p.add_argument('--out', default='tools/README_SECURITY.md')
    args = p.parse_args()
    findings = inspect_data_dir(Path(args.data_dir))
    findings_json = json.dumps(findings, indent=2)
    findings_summary = make_findings_summary(findings)
    content = SECURITY_MD_TEMPLATE.format(findings_summary=findings_summary, findings_json=findings_json)
    outp = Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(content, encoding='utf-8')
    print('Wrote security README to', outp)


if __name__ == '__main__':
    main()
