# 🛠️ PANDUAN PERBAIKAN KEAMANAN - Action Items

**Status Audit:** ✅ Selesai  
**Risk Assessment:** ⚠️ POOR (Backup 33/100) + FAIR (Storage 55/100)  
**Priority:** 🔴 CRITICAL (KDF Iterations)

---

## 📋 Quick Checklist

- [ ] Baca: `AUDIT_RESULTS_SUMMARY.md` (penjelasan lengkap)
- [ ] Review: `.\tools\backup_analysis_out\backup_analysis.html` (visual dashboard)
- [ ] Verifikasi: Backup bisa di-restore dengan sempurna
- [ ] Update: PBKDF2 iterations di AuthManager.java
- [ ] Recompile: Maven build
- [ ] Test: Login / decrypt functions
- [ ] Deploy: Aplikasi dengan KDF baru

---

## 🔴 PRIORITY 1: Upgrade PBKDF2 Iterations (CRITICAL)

### Masalah
```
Current: 65,536 iterations
NIST 2024 Minimum: 210,000
Industry Best: 300,000+
Risk: Password 40-bit bisa di-crack dalam hitungan hari oleh botnet
```

### Solusi: Edit AuthManager.java

**Lokasi File:**
```
src/main/java/id/juman/core/AuthManager.java
```

**Langkah 1: Buka file**
```powershell
code .\src\main\java\id\juman\core\AuthManager.java
```

**Langkah 2: Cari konstanta PBKDF2_ITER**
Cari baris seperti:
```java
private static final int PBKDF2_ITER = 65536;
// atau
new PBEKeySpec(password, salt, 65536, 256);
```

**Langkah 3: Ubah nilai**
```java
// SEBELUM (Old - Weak):
private static final int PBKDF2_ITER = 65536;

// SESUDAH (New - Strong):
private static final int PBKDF2_ITER = 300000;  // NIST 2024 compliant
```

**Opsi Level Keamanan:**
- `210000` = NIST 2024 minimum
- `300000` = Recommended (good balance)
- `500000` = Enterprise level (slower login ~500ms)
- `1000000` = Military grade (very slow, rarely needed)

**Rekomendasi:** Gunakan **300,000** untuk balance antara keamanan dan performance

**Langkah 4: Update ALL occurrences**
Jika ada beberapa tempat:
```java
// Jika ada di constructor
public AuthManager(String password) {
    // Find: 65536, Replace: 300000
}

// Jika ada di static block
static {
    PBKDF2_ITER = 300000;
}

// Jika ada inline dalam PBEKeySpec
new PBEKeySpec(pwd, salt, 300000, 128)  // ubah dari 65536
```

**Langkah 5: Compile & test**
```powershell
# Dari root repo
mvn clean compile

# Run tests jika ada
mvn test

# Package
mvn package
```

**Langkah 6: Manual test login**
1. Run aplikasi: `mvn javafx:run`
2. Buat akun baru atau login ulang
3. Perhatikan timing:
   - PBKDF2 65k: login ~50ms
   - PBKDF2 300k: login ~200-300ms (normal)
   - PBKDF2 500k: login ~500ms+ (acceptable)
4. Pastikan dekripsi file masih berfungsi

**Langkah 7: Verify kemampuan decrypt**
```java
// Test: Encrypt file baru
// Decrypt file baru → harus success
// Decrypt file lama (encrypted dengan 65k) → harus tetap bisa
```

### Migration Path untuk File Lama

**Concern:** File lama dienkripsi dengan PBKDF2 65k, bagaimana decrypt dengan 300k?

**Solusi: Dual-mode support**
```java
public class AuthManager {
    private static final int PBKDF2_ITER_NEW = 300000;  // New
    private static final int PBKDF2_ITER_OLD = 65536;   // Legacy
    
    public static SecretKey deriveKey(String password, byte[] salt, boolean isLegacy) {
        int iterations = isLegacy ? PBKDF2_ITER_OLD : PBKDF2_ITER_NEW;
        // Use iterations...
    }
}
```

File lama: tetap decrypt dengan iter=65k  
File baru: encrypt/decrypt dengan iter=300k

---

## 🟡 PRIORITY 2: Verifikasi & Dokumentasi Backup Format (HIGH)

### Masalah
```
Backup format tidak teridentifikasi (detected as "unknown")
Kami tidak tahu apakah format ZIP, encrypted, atau proprietary
```

### Solusi: Investigasi Backup

**Langkah 1: Cek tipe file**
```powershell
# Windows: Get file header
Get-Content -Encoding Byte -TotalCount 4 `
  "C:\Users\yarda\Documents\juman\juman_backup_2025-11-19T13_29_13_537709Z.zip.jumanbackup" `
  | Format-Hex

# Expected outputs:
# - "50 4B 03 04" = ZIP file (PK signature)
# - "4A 4D 4E 42" = JMNB (our signed backup magic)
# - Random bytes = Encrypted blob
```

**Langkah 2: Coba extract sebagai ZIP**
```powershell
# Gunakan 7-Zip, WinRAR, atau PowerShell:
Expand-Archive `
  -Path "C:\Users\yarda\Documents\juman\juman_backup_2025-11-19T13_29_13_537709Z.zip.jumanbackup" `
  -DestinationPath "C:\tmp\backup_test" `
  -ErrorAction Stop

# Jika berhasil → Backup adalah ZIP
# Jika error → Backup encrypted/corrupted/proprietary
```

**Langkah 3: Jika berhasil extract → cek isinya**
```powershell
Get-ChildItem "C:\tmp\backup_test" -Recurse | Format-List

# Cari:
# - master.key (CRITICAL - jangan ada!)
# - master.key.enc (GOOD - boleh ada)
# - *.jmn files (encrypted files)
# - manifest.json atau config (metadata)
```

**Langkah 4: Dokumentasikan format**
Buat file `docs/BACKUP_FORMAT.md`:
```markdown
# Backup Format Specification

## Format Type
- [ ] ZIP (standard)
- [ ] Signed-Backup (JMNB magic)
- [ ] Encrypted Blob
- [ ] Custom/Proprietary

## Content Structure
- Entry 1: [description]
- Entry 2: [description]
- ...

## Security Checklist
- [ ] No plain master.key
- [ ] HMAC signed
- [ ] Password protected
- [ ] Versioned (can restore old backups)
```

---

## 🟢 PRIORITY 3: Implementasi Header Standard untuk Files (MEDIUM)

### Masalah
```
File Storage tidak semuanya teridentifikasi dengan jelas
File 1: format unknown-binary (tidak bisa verifikasi)
File 2: AES-GCM heuristic (good, tapi tidak pasti)
```

### Solusi: Gunakan Header Standard JMN1

**Step 1: Update CryptoService.java**

Tambahkan method untuk encrypt dengan header:
```java
public class CryptoService {
    private static final byte[] FILE_MAGIC = "JMN1".getBytes();
    private static final byte VERSION = 1;
    
    public static void encryptFileWithHeader(File inputFile, File outputFile, 
                                            SecretKey key, String metadata) 
                        throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            
            // Write header
            fos.write(FILE_MAGIC);                    // 4 bytes: "JMN1"
            fos.write(VERSION);                       // 1 byte: version
            
            // Write metadata
            byte[] metaBytes = metadata.getBytes(StandardCharsets.UTF_8);
            fos.write(metaBytes.length >> 24);
            fos.write(metaBytes.length >> 16);
            fos.write(metaBytes.length >> 8);
            fos.write(metaBytes.length);              // 4 bytes: meta length
            fos.write(metaBytes);                     // N bytes: metadata JSON
            
            // Generate IV
            byte[] iv = new byte[12];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            fos.write(iv);                            // 12 bytes: IV
            
            // Encrypt and write ciphertext + tag
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                fos.write(cipher.update(buffer, 0, bytesRead));
            }
            fos.write(cipher.doFinal());
        }
    }
}
```

**Step 2: Update MainController.java**

Saat encryption file baru, gunakan method dengan header:
```java
// SEBELUM (Old - no header)
cryptoService.encryptFile(file, encryptedFile, masterKey);

// SESUDAH (New - with header)
String metadata = new JSONObject()
    .put("filename", file.getName())
    .put("mimetype", determineMimeType(file))
    .put("timestamp", System.currentTimeMillis())
    .toString();

cryptoService.encryptFileWithHeader(file, encryptedFile, masterKey, metadata);
```

**Step 3: Backward compatibility**

Dekripsi harus support both format:
```java
public static void decryptFile(File encryptedFile, File outputFile, SecretKey key) 
                               throws Exception {
    try (FileInputStream fis = new FileInputStream(encryptedFile);
         FileOutputStream fos = new FileOutputStream(outputFile)) {
        
        byte[] headerCheck = new byte[4];
        fis.read(headerCheck);
        fis.reset();
        
        if (Arrays.equals(headerCheck, "JMN1".getBytes())) {
            // New format with header
            decryptFileWithHeader(fis, fos, key);
        } else {
            // Old format (backward compatibility)
            decryptFileWithoutHeader(fis, fos, key);
        }
    }
}
```

**Step 4: Test migration**
```powershell
# 1. Encrypt file lama (tanpa header) - masih berfungsi
# 2. Decrypt file lama - harus bisa
# 3. Encrypt file baru (dengan header) - harus bisa
# 4. Decrypt file baru - harus bisa
```

---

## Diagram Roadmap

```
TIMELINE:
┌─────────────────────────────────────────────────────────────────┐
│ DAY 1-2 (This Week)                                            │
│ ├─ Read audit results                                          │
│ ├─ Verify backup can restore                                  │
│ └─ Start PBKDF2 update                                         │
├─────────────────────────────────────────────────────────────────┤
│ DAY 3-7 (This Week)                                            │
│ ├─ Update AuthManager.java: PBKDF2 = 300k                     │
│ ├─ Compile & test                                             │
│ ├─ Manual verification                                        │
│ └─ Deploy to production                                       │
├─────────────────────────────────────────────────────────────────┤
│ WEEK 2 (Next Week)                                            │
│ ├─ Investigate backup format                                  │
│ ├─ Implement dual-mode decryption                             │
│ ├─ Document backup spec                                       │
│ └─ Test backup/restore                                        │
├─────────────────────────────────────────────────────────────────┤
│ WEEK 3-4 (Next 2-4 Weeks)                                     │
│ ├─ Add header support (JMN1) for new files                    │
│ ├─ Implement HMAC signing on backups                          │
│ ├─ Implement master.key.enc                                   │
│ └─ Full security audit #2                                     │
└─────────────────────────────────────────────────────────────────┘

SECURITY SCORE PROJECTION:
Before (Current): Storage 55/100, Backup 33/100
After Week 1:     Storage 70/100, Backup 45/100  (KDF upgrade)
After Week 2-4:   Storage 85/100, Backup 75/100  (Full hardening)
```

---

## ✅ Verification Checklist

Setelah setiap perubahan, jalankan audit lagi:

```powershell
# After KDF update:
python .\tools\juman_encryption_audit.py --data-dir "C:\Users\yarda\Documents\juman\storage" --repo-root . --out .\tools\storage_audit_out_v2

python .\tools\juman_encryption_audit.py --backup "C:\Users\yarda\Documents\juman\juman_backup_2025-11-19T13_29_13_537709Z.zip.jumanbackup" --repo-root . --out .\tools\backup_analysis_out_v2

# Bandingkan: score harus naik ✅
```

Expected score improvement:
- KDF 65k: Score ~60/100
- KDF 300k: Score ~75/100  (+15 points)
- Full hardening: Score ~85+/100

---

## 📚 Reference Documentation

- `SECURITY_AUDIT_README.md` — Tool usage & interpretation
- `AUDIT_RESULTS_SUMMARY.md` — Detailed findings
- `docs/PBO.md` — Technical implementation examples
- NIST SP 800-132 — PBKDF2 guidelines

---

**Next Action:** 👉 Start with PRIORITY 1 (KDF update) - ini yang paling critical!

Good luck! 🚀
