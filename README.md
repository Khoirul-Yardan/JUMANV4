JuMan - JustManage (Final)
Java 25 + JavaFX 22.0.2 (Maven)
Storage: Documents/JuMan
Theme: Dark Elegant
Backup: single encrypted zip (.jumanbackup)

Run:
 - mvn clean javafx:run
 - or run.bat (Windows) / run.sh (Linux/Mac)

Important: This is a starter app. Backup file is encrypted with app MasterKey.

---

Security audit tool (new)
-------------------------

I've added a lightweight security audit tool in `tools/security_audit.py`. It can scan hosts for common open ports, fetch HTTP/TLS/SSH info, create/check a SHA256 baseline of a data directory (to detect missing/changed files), and generate an HTML report with a network diagram.

Files added:
- `tools/security_audit.py` — main script
- `tools/requirements.txt` — Python dependencies (requests, matplotlib, networkx)

Additional risk analysis tool:
- `tools/risk_analysis.py` — estimates brute-force times, key-theft and Wi-Fi risks, produces a bar chart PNG and HTML summary.

Usage example for risk analysis:

```powershell
python tools/risk_analysis.py --password-entropy 40 --hash-rate 1000000 --pbkdf2-iters 65536 --attacker-disk-access no --wifi-risk 0.25 --output risk_out
```

Outputs:
- `risk_out/risk_barchart.png` — horizontal bar chart of estimated risks
- `risk_out/risk_report.html` — human-readable report with recommendations

See `tools/` for usage examples and the HTML report output location.

Notes:
- Use the audit tool only on systems/networks you are authorized to test.
- For production-grade scanning, use purpose-built scanners (nmap, openvas, etc.).

PBO (Pemrograman Berorientasi Objek) — konsep yang dipakai di JuManV3
---------------------------------------------------------------

Di bawah ini ringkasan konsep PBO yang hadir di proyek ini, contoh kelas yang relevan, alasan memakai, trade-offs, dan contoh kode kecil (diambil/diadaptasi dari sistem) agar langsung bisa dibaca oleh developer.

1) Enkapsulasi
- Definisi singkat: menyembunyikan detail implementasi dan expose API yang diperlukan.
- Contoh di repo: `CryptoService`, `FileManager`, `AuthManager`.
- Mengapa dipakai: menyederhanakan pemanggilan operasi kripto/file, mengurangi risiko kebocoran detail sensitif.
- Trade-off: jika satu kelas mengurus terlalu banyak tanggung jawab (I/O + policy + UI), enkapsulasi tidak cukup — perlu pemecahan.

Contoh (dari `CryptoService` / `FileManager` - disederhanakan):

```java
// CryptoService.java (interface-like usage)
public class CryptoService {
	// enkapsulasi detail IV/GCM
	public byte[] encrypt(byte[] plain, SecretKey key) throws GeneralSecurityException { ... }
	public byte[] decrypt(byte[] cipher, SecretKey key) throws GeneralSecurityException { ... }
}

// FileManager.java (menggunakan CryptoService tanpa tahu detail)
public class FileManager {
	private final CryptoService crypto;

	public FileManager(CryptoService crypto) {
		this.crypto = crypto; // komposisi
	}

	public String storeEncrypted(File src, SecretKey key) throws IOException {
		byte[] data = Files.readAllBytes(src.toPath());
		byte[] enc = crypto.encrypt(data, key);
		// tulis ke storage, return stored filename
		return "<stored-filename>";
	}
}
```

2) Abstraksi
- Definisi singkat: expose operasi berlevel-tinggi (mis. "encrypt file") sehingga caller tak perlu detail low-level.
- Contoh: `BackupService.createEncryptedBackup(...)` dan `CryptoService`.
- Mengapa dipakai: memudahkan caller dan mengurangi duplikasi.
- Trade-off: jika caller butuh opsi-opsi low-level, abstraksi harus menyediakan hooks atau parameter konfigurasi.

3) Komposisi > Pewarisan
- Definisi singkat: objek "has-a" (memiliki instance lain) digunakan untuk fleksibilitas.
- Contoh: `MainController` dan `LoginController` memakai instance `AuthManager`, `FileManager`, `BackupService`.
- Mengapa dipakai: lebih mudah mengganti implementasi dan testing (mocking).
- Trade-off: jika dependensi dibuat di dalam kelas (new X()), testability menurun. Gunakan constructor injection bila perlu.

Contoh injeksi sederhana (refactor kecil yang direkomendasikan):

```java
// MainController.java (contoh penggunaan constructor injection untuk testability)
public class MainController {
	private final FileManager fileManager;
	private final CryptoService crypto;

	// di aplikasi nyata, framework DI tidak perlu — cukup buat secara manual di JuManApp
	public MainController(FileManager fileManager, CryptoService crypto) {
		this.fileManager = fileManager;
		this.crypto = crypto;
	}

	// metode handler akan memanggil fileManager / crypto
}
```

4) Prinsip SOLID (ringkas)
- SRP: banyak kelas sudah fokus (CryptoService untuk kripto, FileManager untuk I/O). Namun `AuthManager` melakukan beberapa tugas (hashing, file persistence, recovery token) — pertimbangkan memecah `AuthStorage`.
- O/C & DIP: saat ini kelas concrete dipakai langsung. Menambahkan interface (contoh: `ICryptoService`) membantu jika Anda perlu swap implementasi atau mocking di tests.

5) Polimorfisme & Pewarisan
- Saat ini penggunaan pewarisan minimal; komposisi dipilih untuk kesederhanaan. Gunakan interface/abstract class saat butuh beberapa implementasi (mis. hardware keystore vs software crypto).

6) Separation of Concerns
- UI (FXML + Controllers) terpisah dari `core` package (auth, file, crypto, backup). Pastikan controllers hanya mengorkestrasi dan tidak menyuntikkan logic bisnis berlebih.

[Metode PBO](doc/PBO.md)
[Audit](tools/README_AUDIT.md)
[Security](tools/README_SECURITY.md)