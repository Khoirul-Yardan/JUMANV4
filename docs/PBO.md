# PBO (Pemrograman Berorientasi Objek) di JuManV3

Dokumen ini menjelaskan konsep PBO yang dipakai (atau relevan) di proyek JuManV3, contoh kode yang diambil/diadaptasi dari kode proyek, dan perbandingan jelas: "Jika dipakai — kenapa" vs "Jika tidak dipakai — kenapa (trade-off)". Ditujukan untuk developer yang ingin memahami arsitektur dan keputusan desain terkait OOP.

---

## Ringkasan singkat

Project JuManV3 menggunakan struktur berlapis: UI (FXML + Controllers) terpisah dari `core` (auth, crypto, file, backup). Secara umum terlihat penerapan:

- Enkapsulasi: ya (CryptoService, FileManager, AuthManager)
- Abstraksi: ya (CryptoService, BackupService sebagai API tingkat tinggi)
- Komposisi: ya (controllers memegang instance service)
- Pewarisan/Polimorfisme: minim (lebih mengandalkan komposisi)
- Prinsip SOLID: sebagian diterapkan; DIP & O/C dapat ditingkatkan lewat interface/DI

Dokumen ini menjabarkan tiap konsep dan memberikan contoh kode serta rekomendasi.

---

## 1) Enkapsulasi

Deskripsi singkat:
Menjaga detail implementasi (state, algoritma, I/O) tersembunyi di dalam kelas dan hanya mengekspos method yang diperlukan.

Contoh di JuManV3:
- `CryptoService` — method publik `encrypt` / `decrypt` sementara detail IV, tag, dan format file disembunyikan.
- `FileManager` — method seperti `storeEncrypted`, `decryptToTemp` tanpa mengekspos byte-stream handling.

Jika dipakai — kenapa:
- Memudahkan perubahan implementasi (mis. mengganti algoritma) tanpa merusak pemanggil.
- Meningkatkan keamanan: tidak mengekspos detail sensitif (IV/kunci) ke UI.

Jika tidak dipakai — kenapa (trade-off):
- Caller harus menangani detail low-level, meningkatkan potensi bug dan duplikasi kode.
- Namun, pada kasus tertentu caller mungkin butuh kontrol low-level (mis. custom header backup), sehingga enkapsulasi harus menyediakan opsi konfigurasi.

Rekomendasi:
- Pertahankan enkapsulasi; jika butuh kontrol, tambahkan parameter/overload atau callback.

Contoh (disederhanakan, diambil dari kode):

```java
// CryptoService.java (disederhanakan)
public class CryptoService {
    public byte[] encrypt(byte[] plain, SecretKey key) throws GeneralSecurityException {
        // detail IV/GCM/internal tidak dipublikasi
        ...
    }
    public byte[] decrypt(byte[] cipher, SecretKey key) throws GeneralSecurityException {
        ...
    }
}

// FileManager.java (menggunakan CryptoService)
public class FileManager {
    private final CryptoService crypto;
    public FileManager(CryptoService crypto) { this.crypto = crypto; }

    public String storeEncrypted(File src, SecretKey key) throws IOException {
        byte[] data = Files.readAllBytes(src.toPath());
        byte[] enc = crypto.encrypt(data, key);
        Files.write(Path.of("storage", "..."), enc);
        return "stored-filename";
    }
}
```

---

## 2) Abstraksi

Deskripsi singkat:
Menyediakan API ber-level tinggi (mis. "createEncryptedBackup") yang menyamarkan detil implementasi (zip, enkripsi) dari caller.

Contoh di JuManV3:
- `BackupService.createEncryptedBackup(SecretKey)` membuat backup terenkripsi tanpa caller perlu tahu detail zip/encrypt.

Jika dipakai — kenapa:
- Mempercepat pengembangan dan mengurangi kesalahan penggunaan API low-level.

Jika tidak dipakai — kenapa:
- Memberi kebebasan untuk kustomisasi penuh tetapi menambah beban pada pengembang (lebih banyak kode boilerplate / potensi bug).

Rekomendasi:
- Sediakan abstraksi plus opsi konfigurasi (mis. compression level, include/exclude). Jika butuh kontrol penuh, expose advanced API.

---

## 3) Komposisi (has-a) vs Pewarisan (is-a)

Deskripsi singkat:
Komposisi berarti objek memiliki dependensi lain (mis. controller memiliki instance service). Pewarisan berarti subclassing.

Status di JuManV3:
- Umumnya menggunakan komposisi: controllers memegang `AuthManager`, `FileManager`, `BackupService`.
- Pewarisan/minim: tidak banyak class yang extends/overrides behavior.

Jika memakai komposisi — kenapa:
- Lebih fleksibel, mudah mock untuk unit-test, lebih aman untuk reuse.

Jika memakai pewarisan berlebihan — kenapa tidak disarankan:
- Bisa menyebabkan hierarki kacau dan membuat perubahan sulit.

Rekomendasi:
- Pertahankan komposisi. Jika ingin substitusi implementasi, tambahkan interface dan gunakan dependency injection (DI) sederhana.

Contoh refactor kecil (saran): Constructor injection pada controller

```java
public class MainController {
    private final FileManager fileManager;
    public MainController(FileManager fileManager) {
        this.fileManager = fileManager;
    }
}
```

Jika diterapkan:
- Keuntungan: mudah unit-test (pass mock FileManager), mudah swap impl.
- Kekurangan: perlu wiring (di `JuManApp`) untuk membuat instance dan menyuntikkan dependensi.

---

## 4) Prinsip SOLID (ringkasan dan penerapan)

- Single Responsibility (SRP): beberapa kelas sudah mematuhi (CryptoService, FileManager). `AuthManager` gabungan tugas — rekomendasi: pisahkan `AuthStorage`.
- Open/Closed (O/C): tambahkan interface agar layanan dapat diperluas tanpa ubah kode klien.
- Liskov Substitution (LSP): jika menambahkan subclass, pastikan kontrak tidak dilanggar.
- Interface Segregation (ISP): buat interface spesifik jika class memiliki banyak fitur berbeda.
- Dependency Inversion (DIP): saat ini concrete class dipakai langsung — tambah interface dan gunakan DI sederhana.

Perbandingan praktis (Jika dipakai vs tidak):

- Jika menerapkan DIP (interfaces + DI):
  - Pro: testable, fleksibel untuk ganti implementasi
  - Kontra: sedikit boilerplate (interfaces, wiring)

- Jika tidak menerapkan DIP:
  - Pro: cepat implementasi
  - Kontra: sulit testing, sulit mengubah implementasi di masa depan

Rekomendasi prioritas:
1. Tambah `ICryptoService` + buat `CryptoServiceAesGcm` implementasinya
2. Ubah `FileManager`/`BackupService` agar bergantung pada interface
3. Uji dengan unit test (mocking)

---

## 5) Polimorfisme

Catatan:
- Saat ini minim; gunakan interface/abstract class untuk mendukung multiple implementations (mis. `CryptoServiceSoftware` vs `CryptoServiceHardware`).

Jika dipakai:
- Memudahkan penggantian implementasi (mis. pindah ke HSM) tanpa ubah kode aplikasi.

Jika tidak dipakai:
- Lebih sederhana, tapi mengunci implementasi.

---

## 6) Separation of Concerns (SoC)

Deskripsi singkat:
- UI (FXML+Controller) harus sekadar orchestration; core package menangani logic.

Status di JuManV3:
- Sudah ada pemisahan awal antara `ui` dan `core` packages. Pastikan controller tidak melakukan heavy-lifting.

Jika SoC diterapkan konsisten:
- Lebih mudah maintenance, bisa ganti UI tanpa ubah core.

Jika tidak:
- Codebase sulit di-scale dan diuji.

Rekomendasi:
- Keluarkan validasi/logic bisnis dari controller ke service; controller hanya ambil input dan panggil service.

---

## 7) Resource management & error handling

Rekomendasi praktis:
- Semua I/O gunakan try-with-resources.
- Tangani exception di service dan kembalikan error object atau exception yang meaningful ke UI.
- Tambahkan central logging (slf4j) untuk core services.

---

## Contoh kode tambahan: Interface `ICryptoService` dan DTO `FileMetadata`

```java
// ICryptoService.java (contoh interface sederhana)
public interface ICryptoService {
    byte[] encrypt(byte[] plain, SecretKey key) throws GeneralSecurityException;
    byte[] decrypt(byte[] cipher, SecretKey key) throws GeneralSecurityException;
}

// FileMetadata.java (DTO untuk menyimpan metadata file, rekomendasi ketimbang encode di filename)
public class FileMetadata {
    private final String id;
    private final String originalName;
    private final String storedName;
    private final Instant createdAt;

    public FileMetadata(String id, String originalName, String storedName, Instant createdAt) {
        this.id = id;
        this.originalName = originalName;
        this.storedName = storedName;
        this.createdAt = createdAt;
    }
    // getters...
}
```

Jika memakai DTO seperti `FileMetadata`, operasi listing UI jadi lebih mudah: tampilkan `originalName` dan gunakan `storedName` untuk operasi delete/export.

---

## Kesimpulan dan langkah selanjutnya

Ringkas:
- JuManV3 sudah menerapkan banyak prinsip OOP dasar (enkapsulasi, komposisi, abstraksi) dan separation of concerns di level package.
- Untuk meningkatkan kualitas kode lebih lanjut, saya rekomendasikan menambahkan interface untuk layanan inti, memisahkan responsibility penyimpanan dari kebijakan (AuthStorage), dan menerapkan constructor injection untuk meningkatkan testability.

Langkah yang bisa saya lakukan berikutnya (opsional):
1. Buat `ICryptoService` dan `CryptoServiceAesGcm` sebagai contoh implementasi beserta perubahan kecil pada `FileManager` (refactor).  
2. Buat `docs/PBO.md` ini (sudah dibuat).  
3. Tambah contoh unit-test JUnit untuk `FileManager` round-trip.

Jika Anda setuju, saya bisa langsung membuat PR-style patch untuk langkah 1 (interface + refactor contoh) dan test minimal.

---

Dokumen dibuat pada: 2025-11-06
 
---

## Contoh kode nyata dari aplikasi (potongan dan penjelasan)

Di bawah ini beberapa potongan kode nyata yang menunjukkan konsep PBO yang diterapkan di proyek. Untuk tiap potongan saya jelaskan "kenapa dipakai" dan "jika tidak dipakai (trade-off)".

1) `CryptoService.encryptFile` — enkapsulasi + resource management

```java
// dari src/main/java/id/juman/core/CryptoService.java
public static void encryptFile(File in, File out, SecretKey key) throws Exception {
    byte[] iv = new byte[IV_LENGTH]; RNG.nextBytes(iv);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcm = new GCMParameterSpec(TAG_LENGTH, iv);
    cipher.init(Cipher.ENCRYPT_MODE, key, gcm);
    try (FileOutputStream fos = new FileOutputStream(out);
         FileInputStream fis = new FileInputStream(in);
         CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
        fos.write(iv); // write iv first
        byte[] buf = new byte[4096]; int r;
        while ((r = fis.read(buf)) != -1) cos.write(buf, 0, r);
    }
}
```

Kenapa dipakai:
- Enkapsulasi detail kriptografi (IV, cipher init, tag) di satu kelas.
- try-with-resources memastikan streams ditutup otomatis (resource management).

Jika tidak dipakai (trade-off):
- Caller harus mengurus detail enkripsi dan penutupan stream → duplikasi kode dan potensi kebocoran resource/security.

2) `FileManager.storeEncrypted` — abstraksi operasi penyimpanan dan komposisi

```java
// dari src/main/java/id/juman/core/FileManager.java
public String storeEncrypted(File input, SecretKey key) throws Exception {
    String id = UUID.randomUUID().toString();
    String orig = input.getName().replaceAll("[^A-Za-z0-9._-]", "_");
    File out = storageDir.resolve(id + "__" + orig + ".jmn").toFile();
    CryptoService.encryptFile(input, out, key);
    try { Files.deleteIfExists(input.toPath()); } catch (Exception e) {}
    return out.getName();
}
```

Kenapa dipakai:
- Abstraksi "storeEncrypted" membuat caller (controller) cukup memanggil satu method tanpa detail I/O.
- Komposisi: `FileManager` memanggil `CryptoService` (has-a), memisahkan tanggung jawab.

Jika tidak dipakai:
- UI/controller harus menggabungkan logika enkripsi + penulisan file, mengurangi reusability dan testability.

3) `AuthManager.pbkdf2` dan `setPassword` — enkapsulasi logika autentikasi

```java
// dari src/main/java/id/juman/core/AuthManager.java
private byte[] pbkdf2(char[] password, byte[] salt) throws Exception {
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
    return skf.generateSecret(spec).getEncoded();
}

public void setPassword(String pwd) throws Exception {
    byte[] salt = new byte[16]; rng.nextBytes(salt);
    byte[] hash = pbkdf2(pwd.toCharArray(), salt);
    passwordSalt = Base64.getEncoder().encodeToString(salt);
    passwordHash = Base64.getEncoder().encodeToString(hash);
    passwordChanged = true;
    // persist to config
    Properties p = new Properties();
    p.setProperty("username", username);
    p.setProperty("passwordChanged", String.valueOf(passwordChanged));
    p.setProperty("passwordHash", passwordHash);
    p.setProperty("passwordSalt", passwordSalt);
    try (OutputStream os = Files.newOutputStream(configFile, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) { p.store(os, "JuMan config"); }
}
```

Kenapa dipakai:
- Enkapsulasi logika hash dan persistensi di `AuthManager` menjaga controller tetap sederhana dan meningkatkan keamanan (PBKDF2 dipakai di satu tempat).

Jika tidak dipakai:
- Logic hashing/IO tersebar di beberapa tempat → risiko implementasi yang tidak konsisten.

4) `MainController.initialize` & penggunaan service — komposisi dan separation of concerns

```java
// dari src/main/java/id/juman/ui/MainController.java
public void initialize() {
    try {
        Path data = AuthManager.getInstance().getDataDir();
        fileManager = new FileManager(data);
        backupService = new BackupService(data);
        masterKey = AuthManager.getInstance().getMasterKey();
        infoLabel.setText("Storage: " + data.toAbsolutePath().toString());
        refreshList();
    } catch (Exception e){ infoLabel.setText("Init error: " + e.getMessage()); }
}
```

Kenapa dipakai:
- Controller bertindak sebagai orchestrator (SoC) — membuat instance service dan memanggil method-level tinggi (storeEncrypted, createEncryptedBackup) daripada mengimplementasikan logika sendiri.

Jika tidak dipakai:
- Controller akan bercampur dengan logika bisnis (I/O/crypto), menyulitkan testing dan pemeliharaan.

---

Jika Anda mau, saya bisa juga:
- Menambahkan bagian kecil di `docs/PBO.md` yang menunjukkan saran refactor (mis. menambahkan `ICryptoService` dan menggunakan constructor injection pada `MainController`) dan membuat patch contoh.
- Atau langsung menerapkan refactor contoh (interface + satu controller) dan menambahkan unit test.

Dokumen diperbarui: 2025-11-06
 
---

## Contoh Implementasi — Petunjuk File-per-File (Praktis)

Di bawah ini adalah panduan konkret (file + lokasi method) untuk perubahan keamanan yang direkomendasikan. Salin-potong potongan kode ini ke file yang disebutkan dan letakkan method baru di lokasi yang diindikasikan.

- **`src/main/java/id/juman/core/AuthManager.java`**
  - Letakkan: setelah method `pbkdf2(...)` atau dekat area yang menangani `masterKey`/IO.
  - Tambahkan imports jika belum ada: `javax.crypto.*`, `javax.crypto.spec.GCMParameterSpec`, `javax.crypto.spec.SecretKeySpec`, `java.io.*`, `java.nio.file.*`, `java.security.*`, `java.util.*`, `java.nio.charset.StandardCharsets`.
  - Tujuan: enkripsi `master.key` menjadi `master.key.enc` menggunakan password-derived AES key dan menyediakan method migrasi.

Contoh (paste ke `AuthManager`):

```java
private static final String MASTER_KEY_ENC_FILENAME = "master.key.enc";
private static final byte[] MASTER_MAGIC = "JMNK".getBytes(StandardCharsets.US_ASCII);
private static final int PBKDF2_ITER = 200_000; // uji performa pada target hardware
private static final int SALT_LEN = 16;
private static final int IV_LEN = 12;
private static final int TAG_LEN = 128;

private SecretKey deriveAesKeyFromPassword(char[] password, byte[] salt, int iterations, int keyBits) throws Exception {
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
    byte[] keyBytes = skf.generateSecret(spec).getEncoded();
    return new SecretKeySpec(keyBytes, "AES");
}

public void encryptAndStoreMasterKey(char[] password) throws Exception {
    if (masterKey == null) throw new IllegalStateException("masterKey not initialized");
    SecureRandom rng = new SecureRandom();
    byte[] salt = new byte[SALT_LEN]; rng.nextBytes(salt);
    SecretKey wrapKey = deriveAesKeyFromPassword(password, salt, PBKDF2_ITER, 256);

    byte[] iv = new byte[IV_LEN]; rng.nextBytes(iv);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcm = new GCMParameterSpec(TAG_LEN, iv);
    cipher.init(Cipher.ENCRYPT_MODE, wrapKey, gcm);

    byte[] plain = masterKey.getEncoded();
    byte[] cipherText = cipher.doFinal(plain);

    Path out = dataDir.resolve(MASTER_KEY_ENC_FILENAME);
    try (DataOutputStream dos = new DataOutputStream(Files.newOutputStream(out, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING))) {
        dos.write(MASTER_MAGIC);                 // 4 bytes magic
        dos.writeByte(1);                        // version
        dos.writeInt(salt.length); dos.write(salt);
        dos.writeInt(iv.length); dos.write(iv);
        dos.writeInt(cipherText.length); dos.write(cipherText);
    }
}

public SecretKey loadMasterKeyFromEncrypted(char[] password) throws Exception {
    Path in = dataDir.resolve(MASTER_KEY_ENC_FILENAME);
    if (!Files.exists(in)) return null;
    try (DataInputStream dis = new DataInputStream(Files.newInputStream(in))) {
        byte[] magic = new byte[4]; dis.readFully(magic);
        if (!Arrays.equals(magic, MASTER_MAGIC)) throw new IOException("Bad master.key.enc magic");
        int version = dis.readUnsignedByte();
        int saltLen = dis.readInt(); byte[] salt = new byte[saltLen]; dis.readFully(salt);
        int ivLen = dis.readInt(); byte[] iv = new byte[ivLen]; dis.readFully(iv);
        int ctLen = dis.readInt(); byte[] ct = new byte[ctLen]; dis.readFully(ct);

        SecretKey wrapKey = deriveAesKeyFromPassword(password, salt, PBKDF2_ITER, 256);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcm = new GCMParameterSpec(TAG_LEN, iv);
        cipher.init(Cipher.DECRYPT_MODE, wrapKey, gcm);
        byte[] plain = cipher.doFinal(ct);
        return new SecretKeySpec(plain, "AES");
    }
}
```

- **Migrasi**: lakukan check pada startup; jika `master.key` ada dan `master.key.enc` tidak ada, minta password pada user (dialog JavaFX), panggil `encryptAndStoreMasterKey(password)` lalu hapus `master.key` setelah `secureOverwrite`.


- **`src/main/java/id/juman/core/CryptoService.java`**
  - Letakkan: ganti/extend method `encryptFile`/`decryptFile` dengan format header-aware.
  - Tujuan: menulis header (magic, version, metadata length, metadata, IV) sebelum ciphertext sehingga file tetap bisa dikenali meski ekstensi diubah.

Contoh helper (paste ke `CryptoService`):

```java
private static final byte[] FILE_MAGIC = "JMN1".getBytes(StandardCharsets.US_ASCII);
private static final int HEADER_VERSION = 1;

public static void encryptFileWithHeader(File in, File out, SecretKey key, Map<String,String> meta) throws Exception {
    byte[] iv = new byte[12]; SecureRandom rng = new SecureRandom(); rng.nextBytes(iv);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));

    byte[] metaJson = "{}".getBytes(StandardCharsets.UTF_8);
    if (meta != null && !meta.isEmpty()) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        boolean first = true;
        for (Map.Entry<String,String> e : meta.entrySet()) {
            if (!first) sb.append(",");
            sb.append("\"").append(e.getKey()).append("\":\"").append(e.getValue()).append("\"");
            first = false;
        }
        sb.append("}");
        metaJson = sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    try (FileOutputStream fos = new FileOutputStream(out);
         CipherOutputStream cos = new CipherOutputStream(fos, cipher);
         FileInputStream fis = new FileInputStream(in)) {
        fos.write(FILE_MAGIC);
        fos.write(HEADER_VERSION);
        fos.write(ByteBuffer.allocate(4).putInt(metaJson.length).array());
        fos.write(metaJson);
        fos.write(iv); // fixed 12 bytes
        byte[] buf = new byte[4096]; int r;
        while ((r = fis.read(buf)) != -1) cos.write(buf, 0, r);
    }
}

public static Map<String,Object> readHeader(Path encrypted) throws Exception {
    try (InputStream is = Files.newInputStream(encrypted, StandardOpenOption.READ)) {
        byte[] magic = new byte[4]; if (is.read(magic) != 4) throw new IOException("Bad file");
        if (!Arrays.equals(magic, FILE_MAGIC)) throw new IOException("Unknown format");
        int version = is.read();
        byte[] lenb = new byte[4]; if (is.read(lenb) != 4) throw new IOException("Bad meta len");
        int metaLen = ByteBuffer.wrap(lenb).getInt();
        byte[] metaJson = new byte[metaLen]; if (is.read(metaJson) != metaLen) throw new IOException("Bad meta");
        byte[] iv = new byte[12]; if (is.read(iv) != 12) throw new IOException("Bad iv");
        Map<String,Object> ret = new HashMap<>();
        ret.put("version", version);
        ret.put("meta", new String(metaJson, StandardCharsets.UTF_8));
        ret.put("iv", iv);
        return ret;
    }
}
```

 - Setelah menambahkan, ubah pemanggil (mis. `FileManager.storeEncrypted(...)`) untuk memakai `encryptFileWithHeader(...)` dan tambahkan metadata `originalName` sehingga UI dapat menampilkan nama asli.


- **`src/main/java/id/juman/core/BackupService.java`**
  - Letakkan: di method yang membuat ZIP/backup; tambahkan HMAC signing dan verifikasi di method restore.
  - Tujuan: hindari menyertakan `master.key` di backup dan tambahkan integritas backup dengan `HmacSHA256`.

Contoh potongan (paste ke `BackupService`):

```java
private static final byte[] BACKUP_MAGIC = "JMNB".getBytes(StandardCharsets.US_ASCII);

public Path createSignedBackup(Path zipPath, SecretKey hmacKey) throws Exception {
    byte[] zipBytes = Files.readAllBytes(zipPath);
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(hmacKey.getEncoded(), "HmacSHA256"));
    byte[] tag = mac.doFinal(zipBytes);

    Path signed = zipPath.resolveSibling(zipPath.getFileName().toString() + ".signed");
    try (OutputStream os = Files.newOutputStream(signed, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
        os.write(BACKUP_MAGIC);
        os.write(1); // version
        os.write(ByteBuffer.allocate(4).putInt(tag.length).array()); os.write(tag);
        os.write(zipBytes);
    }
    return signed;
}

public boolean verifySignedBackup(Path signed, SecretKey hmacKey) throws Exception {
    try (DataInputStream dis = new DataInputStream(Files.newInputStream(signed))) {
        byte[] magic = new byte[4]; dis.readFully(magic);
        if (!Arrays.equals(magic, BACKUP_MAGIC)) throw new IOException("Bad backup");
        int version = dis.readUnsignedByte();
        int tagLen = dis.readInt(); byte[] tag = new byte[tagLen]; dis.readFully(tag);
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        byte[] buf = new byte[4096]; int r;
        while ((r = dis.read(buf)) != -1) bout.write(buf, 0, r);
        byte[] zipBytes = bout.toByteArray();

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(hmacKey.getEncoded(), "HmacSHA256"));
        byte[] expected = mac.doFinal(zipBytes);
        return MessageDigest.isEqual(expected, tag);
    }
}
```

 - Catatan: kunci HMAC (`hmacKey`) harus dilindungi (sama levelnya dengan master key). Jangan simpan `master.key` plain di zip — exclude `master.key` saat membuat ZIP.


- **`src/main/java/id/juman/core/FileManager.java`**
  - Letakkan: gunakan `findStoredPath(...)` pada semua panggilan decrypt/delete; setelah header-aware `CryptoService` dibuat, gunakan header untuk menampilkan nama asli.
  - Contoh penggunaan (di `decryptToTemp` atau `decryptTo`):

```java
Path stored = findStoredPath(requestedStoredName);
if (stored == null) throw new FileNotFoundException("Stored file not found: " + requestedStoredName);
Map<String,Object> header = CryptoService.readHeader(stored);
SecretKey master = AuthManager.getInstance().getMasterKey();
// implement decryptFileWithHeader(...) di CryptoService untuk men-decrypt dan menulis ke target
CryptoService.decryptFileWithHeader(stored.toFile(), target.toFile(), master);
```

 - Pastikan `deleteStored` melakukan `secureOverwrite(...)` sebelum menghapus file (sudah diimplementasikan pada perubahan sebelumnya).


- **`src/main/java/id/juman/ui/MainController.java`**
  - Letakkan: di `initialize()` tambahkan migrasi `master.key` → `master.key.enc`.
  - Contoh snippet (paste di awal `initialize()` setelah load dataDir):

```java
Path data = AuthManager.getInstance().getDataDir();
Path plainMaster = data.resolve("master.key");
Path encMaster = data.resolve("master.key.enc");
if (Files.exists(plainMaster) && !Files.exists(encMaster)) {
    Optional<String> pwd = promptPassword("Please create a password to protect master key");
    if (pwd.isPresent()) {
        AuthManager.getInstance().encryptAndStoreMasterKey(pwd.get().toCharArray());
        FileManager.secureOverwrite(plainMaster);
        Files.deleteIfExists(plainMaster);
    }
}
```

  - `promptPassword(...)` harus berupa dialog JavaFX yang menyembunyikan input (gunakan custom `Dialog<String>` dengan `PasswordField`).


### Catatan penting
 - Uji performa KDF (`PBKDF2_ITER`) pada mesin target — iterasi tinggi mempengaruhi UX (login, migrasi).
 - Secure-delete pada SSD/modern FS tidak menjamin penghapusan fisik (TRIM/wear-leveling). Dokumentasikan batasan ini di README.
 - Jika memungkinkan, gunakan Argon2 via library (lebih aman untuk password hashing) — pertimbangkan perubahan bergantung pada kebutuhan distribusi.

---

Jika Anda ingin, saya dapat menerapkan patch otomatis (satu per file) ke repository sekarang. Pilih: `terapkan semua` atau `terapkan bertahap (AuthManager dulu)`.

