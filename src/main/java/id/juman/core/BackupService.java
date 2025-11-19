
package id.juman.core;

import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.ZipParameters;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Path;
import java.time.Instant;

public class BackupService {
    private final Path dataDir;
    public BackupService(Path dataDir){
        this.dataDir = dataDir;
    }

    // create one zip containing storage folder and config; then encrypt the zip using CryptoService
    public File createEncryptedBackup(SecretKey masterKey) throws Exception {
        Path storage = dataDir.resolve("storage");
        String name = "juman_backup_" + Instant.now().toString().replaceAll("[:.]","_") + ".zip";
        File zipOut = dataDir.resolve(name).toFile();
        // use zip4j to create zip (no password) then encrypt via CryptoService to .jumanbackup
        ZipFile zf = new ZipFile(zipOut);
        ZipParameters params = new ZipParameters();
        if (storage.toFile().exists()) zf.addFolder(storage.toFile(), params);
        // include config and master.key and recovery.txt
        File cfg = dataDir.resolve("config.properties").toFile();
        if (cfg.exists()) zf.addFile(cfg, params);
        File mk = dataDir.resolve("master.key").toFile();
        if (mk.exists()) zf.addFile(mk, params);
        File rec = dataDir.resolve("recovery.txt").toFile();
        if (rec.exists()) zf.addFile(rec, params);
        // now encrypt zipOut -> .jumanbackup
        File enc = dataDir.resolve(name + ".jumanbackup").toFile();
        CryptoService.encryptFile(zipOut, enc, masterKey);
        // delete raw zip
        zipOut.delete();
        return enc;
    }

    // restore an encrypted backup (.jumanbackup) by decrypting with masterKey and extracting into targetDir
    public void restoreEncryptedBackup(File encFile, SecretKey masterKey, Path targetDir) throws Exception {
        // decrypt to a temp zip
        File tmpZip = File.createTempFile("juman_restore_", ".zip");
        try {
            CryptoService.decryptFile(encFile, tmpZip, masterKey);
            ZipFile zf = new ZipFile(tmpZip);
            try {
                zf.extractAll(targetDir.toAbsolutePath().toString());
            } finally {
                // ZipFile has no close method that throws; let it be GC'd
            }
        } finally {
            try { tmpZip.delete(); } catch (Exception ignore) {}
        }
    }
}
