# JuMan Security Audit Tool

**Comprehensive encryption and backup security analysis untuk JuMan.**

## Deskripsi

Tool ini menganalisis keamanan:
- **File Terenkripsi**: Memeriksa format, parameter enkripsi, dan memberikan scoring keamanan
- **File Backup**: Menganalisis format backup, kehadiran master key, dan risiko kompromi

## Fitur Utama

✓ **Security Scoring** (0-100): Evaluasi keamanan file/backup  
✓ **Attack Simulation**: Estimasi waktu brute-force terhadap berbagai skenario  
✓ **Visualization**: Dashboard dengan diagram gauge, heatmap, dan grafik  
✓ **Detailed Reports**: HTML dashboard + JSON data terstruktur  

## Install Dependencies

```powershell
pip install matplotlib jinja2 numpy
```

## Cara Penggunaan

### 1. Scan Storage Terenkripsi

Analisis semua file terenkripsi dalam folder storage:

```powershell
# Dari root repo (C:\xampp\htdocs\JUMANV4)
python .\tools\juman_encryption_audit.py --data-dir "C:\Users\yarda\Documents\juman\storage" --repo-root . --out .\tools\storage_audit_out
```

**Output:**
- `storage_audit_out\audit_report.html` — Dashboard dengan semua diagram
- `storage_audit_out\audit_report.json` — Data terperinci per file
- `storage_audit_out\*.png` — Diagram individual (histogram, pie, heatmap, dll)

### 2. Analisis File Backup

Analisis keamanan satu file backup:

```powershell
# Dari root repo
python .\tools\juman_encryption_audit.py --backup "C:\Users\yarda\Documents\juman\juman_backup_2025-11-19T13_29_13_537709Z.zip.jumanbackup" --repo-root . --out .\tools\backup_analysis_out
```

**Output:**
- `backup_analysis_out\backup_analysis.html` — Dashboard backup dengan scoring
- `backup_analysis_out\backup_analysis.json` — Temuan terperinci + attack scenarios
- `backup_analysis_out\security_gauge.png` — Gauge skor keamanan
- `backup_analysis_out\attack_scenarios.png` — Heatmap waktu crack
- `backup_analysis_out\kdf_comparison.png` — Perbandingan KDF

## Interpretasi Hasil

### Security Score Levels

| Skor | Level | Arti |
|------|-------|------|
| 0-29 | **CRITICAL** | 🚨 Tindakan segera diperlukan |
| 30-49 | **POOR** | ⚠️ Masalah keamanan signifikan |
| 50-69 | **FAIR** | ⚠️ Dapat diterima, perbaikan disarankan |
| 70-100 | **GOOD** | ✓ Keamanan kuat |

### Attack Scenarios Heatmap

Menunjukkan estimasi **tahun** untuk crack password (sumbu Y) vs attacker types (sumbu X):

- **Merah**: < 1 detik (CRITICAL — password sangat lemah)
- **Orange**: < 100 tahun (HIGH RISK)
- **Yellow**: < 10,000 tahun (MEDIUM RISK)
- **Green**: > 10,000 tahun (SAFE)

### KDF Strength

**Current:** Iterasi yang dipakai sekarang (dari `AuthManager.java`)  
**NIST Min:** 210,000 (standar minimum NIST 2024)  
**Industry Best:** 500,000 (rekomendasi industri)

Jika current < 200,000 → **upgrade segera ke 300,000+**

## Temuan Kritis

### ⚠️ Jika Backup Berisi `master.key` Plain

**Status:** 🚨 **CRITICAL**

**Artinya:**
- Backup Anda mengandung kunci master terenkripsi dalam **plain text**
- Jika backup dicuri/dikompromi → **seluruh sistem terkompromi**
- Attacker bisa membuka semua file terenkripsi tanpa tahu password Anda

**Aksi Segera:**
1. Ganti/rotate master key
2. Re-encrypt semua file dengan master key baru
3. **Hapus backup lama** yang berisi master key plain
4. Generate backup baru **tanpa** master key
5. Implementasi `master.key.enc` (master key terenkripsi dengan password)

### ✓ Backup Tanpa `master.key`

Ini OK — backup Anda tidak berisi kunci master.  
Tetap:
- Jaga keamanan password/passphrase
- Simpan backup di lokasi aman terpisah

## Panduan Peningkatan Keamanan

### 1. Tingkatkan KDF Iterations

Jika current < 200,000:

```java
// Di AuthManager.java, ganti:
private static final int PBKDF2_ITER = 65536;

// Menjadi:
private static final int PBKDF2_ITER = 300000;  // atau 500000 untuk enterprise
```

Recompile dan restart aplikasi.

### 2. Encrypt Master Key

Implementasikan `master.key.enc`:

```java
// Backup hanya master.key.enc, bukan plain master.key
// Master key dienkripsi dengan password + PBKDF2-derived key
```

Lihat `docs/PBO.md` untuk contoh implementasi Java.

### 3. Add HMAC Signing ke Backup

Backup harus signed dengan HMAC-SHA256 untuk integritas:

```java
// Backup format: [JMNB magic] [version] [hmac_tag] [zip_data]
// Verifikasi HMAC saat restore
```

### 4. Strong Password Policy

Pastikan password/passphrase:
- **Minimal 16 karakter**
- Mix: UPPERCASE + lowercase + digits + special chars
- **Entropy ≥ 60 bits** (seperti di heatmap)

## Contoh Output

### HTML Report (backup_analysis.html)

```
┌─────────────────────────────────────────────┐
│ 🔐 JuMan Backup Security Analysis           │
├─────────────────────────────────────────────┤
│ Security Score: 65/100 - FAIR              │
│ Format: zip (contains entries)              │
│ Master Key Plain: NO - OK ✓                 │
│ Master Key Encrypted: NO (not present)      │
├─────────────────────────────────────────────┤
│ Diagrams:                                   │
│ • Security Gauge (65/100)                   │
│ • Attack Scenarios (heatmap)                │
│ • KDF Comparison                            │
│ • Brute Force Estimates                     │
└─────────────────────────────────────────────┘
```

### JSON Report (backup_analysis.json)

```json
{
  "security_assessment": {
    "score": 65,
    "level": "FAIR",
    "warnings": ["KDF: Fair (65k-200k), consider raising to 300k+"],
    "recommendations": ["Increase PBKDF2 iterations to 300,000 or more"]
  },
  "attack_scenarios": [
    {
      "entropy_bits": 40,
      "attacker": "Local (CPU GPU)",
      "years": 125000.5,
      "feasibility": "SAFE"
    },
    ...
  ]
}
```

## Troubleshooting

### Error: ModuleNotFoundError: No module named 'matplotlib'

```powershell
pip install matplotlib jinja2 numpy
```

### Error: "Backup not found"

Pastikan path backup benar (gunakan absolute path):

```powershell
python .\tools\juman_encryption_audit.py --backup "C:\Users\yarda\Documents\juman\juman_backup_....jumanbackup" --repo-root . --out .\tools\backup_analysis_out
```

### Storage folder tampak kosong di Explorer

Jalankan PowerShell command untuk lihat hidden files:

```powershell
Get-ChildItem -LiteralPath 'C:\Users\yarda\Documents\juman\storage' -Force -Recurse | Format-List FullName,Attributes,Length
```

## Quick Start Commands (Copy-Paste)

```powershell
# 1. Install dependencies
pip install matplotlib jinja2 numpy

# 2. Scan storage
python .\tools\juman_encryption_audit.py --data-dir "C:\Users\yarda\Documents\juman\storage" --repo-root . --out .\tools\storage_audit_out

# 3. Analyze backup
python .\tools\juman_encryption_audit.py --backup "C:\Users\yarda\Documents\juman\juman_backup_2025-11-19T13_29_13_537709Z.zip.jumanbackup" --repo-root . --out .\tools\backup_analysis_out

# 4. Open reports (Windows)
start .\tools\storage_audit_out\audit_report.html
start .\tools\backup_analysis_out\backup_analysis.html
```

---

**Generated by JuMan Security Audit Tool**  
Version 1.0 | Last Updated: 2025-11-19
