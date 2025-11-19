# JuMan Tools — Secure manager & Audit

File ini menjelaskan penggunaan skrip Python yang ditambahkan untuk meningkatkan keamanan dan melakukan audit ringan.

File utama:
- `tools/juman_secure.py` — manajer penyimpanan terenkripsi: inisialisasi data dir, enkripsi/dekripsi file, secure delete, backup/restore.
- `tools/juman_audit_full.py` — audit lengkap: analisa konfigurasi, serangan kamus (terbatas), brute-force terbatas (opsional), dan diagram komponen + laporan HTML (Bahasa Indonesia).
- `tools/requirements_full.txt` — dependency Python yang diperlukan.

Instalasi (misal di PowerShell):

```powershell
cd C:\xampp\htdocs\JUMANV4\tools
python -m pip install -r requirements_full.txt
```

Contoh penggunaan `juman_secure.py`:

- Inisialisasi data dir (wajib) dengan password:

```powershell
python juman_secure.py init --password "PasswordKuat"
```

- Simpan file terenkripsi:

```powershell
python juman_secure.py store C:\path\to\file.pdf --password "PasswordKuat"
```

- Daftar file tersimpan:

```powershell
python juman_secure.py list
```

- Ekspor (dekripsi) file tersimpan:

```powershell
python juman_secure.py get <stored_name> --password "PasswordKuat" --out C:\path\out.pdf
```

- Hapus aman file tersimpan:

```powershell
python juman_secure.py delete <stored_name> --password "PasswordKuat"
```

- Buat backup terenkripsi:

```powershell
python juman_secure.py backup --password "PasswordKuat"
```

- Kembalikan backup:

```powershell
python juman_secure.py restore C:\path\to\backup.jumanbackup --password "PasswordKuat"
```

Audit keamanan (contoh):

```powershell
python juman_audit_full.py --output tools\juman_audit_out
```

Opsi tambahan: `--bruteforce` untuk brute-force terbatas (sangat mahal), `--wordlist` untuk wordlist kustom.

Peringatan: Brute-force sangat mahal dan harus dijalankan hanya untuk pengujian di lingkungan lokal. Secure overwrite tidak menjamin penghapusan pada SSD/volume dengan snapshot/backup otomatis.
