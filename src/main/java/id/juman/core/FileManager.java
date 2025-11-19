
package id.juman.core;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class FileManager {
    private final Path storageDir;

    public FileManager(Path dataDir) throws IOException {
        this.storageDir = dataDir.resolve("storage");
        if (!Files.exists(storageDir))
            Files.createDirectories(storageDir);
    }

    public String storeEncrypted(File input, SecretKey key) throws Exception {
        String id = UUID.randomUUID().toString();
        // include original filename in stored filename for easier export (sanitized)
        String orig = input.getName().replaceAll("[^A-Za-z0-9._-]", "_");
        File out = storageDir.resolve(id + "__" + orig + ".jmn").toFile();
        CryptoService.encryptFile(input, out, key);
        // try to hide the stored file on Windows Explorer (dos attributes)
        try {
            Path outp = out.toPath();
            // set hidden attribute if supported
            try { Files.setAttribute(outp, "dos:hidden", true, LinkOption.NOFOLLOW_LINKS); } catch (UnsupportedOperationException ignore) {}
            try { Files.setAttribute(outp, "dos:system", true, LinkOption.NOFOLLOW_LINKS); } catch (UnsupportedOperationException ignore) {}
        } catch (Exception ignore) {}
        // best-effort delete original
        try {
            Files.deleteIfExists(input.toPath());
        } catch (Exception e) {
        }
        return out.getName();
    }

    public File decryptToTemp(String storedFilename, SecretKey key) throws Exception {
        Path p = findStoredPath(storedFilename);
        if (p == null)
            throw new IOException("Stored file not found");
        // try to preserve original extension so OS can pick correct default app
        String orig = storedFilename;
        int idx = storedFilename.indexOf("__");
        String ext = "";
        if (idx >= 0) {
            orig = storedFilename.substring(idx + 2);
            if (orig.endsWith(".jmn"))
                orig = orig.substring(0, orig.length() - 4);
        }
        int dot = orig.lastIndexOf('.');
        if (dot >= 0)
            ext = orig.substring(dot + 1);
        File tmp;
        if (!ext.isEmpty()) {
            tmp = Files.createTempFile("juman_", "." + ext).toFile();
        } else {
            tmp = Files.createTempFile("juman_", ".dec").toFile();
        }
        CryptoService.decryptFile(p.toFile(), tmp, key);
        tmp.deleteOnExit();
        return tmp;
    }

    /** Decrypt a stored file to a given destination file. */
    public void decryptTo(File destination, String storedFilename, SecretKey key) throws Exception {
        Path p = findStoredPath(storedFilename);
        if (p == null)
            throw new IOException("Stored file not found");
        CryptoService.decryptFile(p.toFile(), destination, key);
    }

    public List<String> listStored() throws IOException {
        List<String> out = new ArrayList<>();
        if (Files.exists(storageDir)) {
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(storageDir)) {
                for (Path p : ds) {
                    if (Files.isRegularFile(p))
                        out.add(p.getFileName().toString());
                }
            }
        }
        return out;
    }

    /**
     * Try to locate the actual stored file path for a given stored filename.
     * This is tolerant to missing extensions or user-renamed files.
     */
    private Path findStoredPath(String storedFilename) throws IOException {
        Path direct = storageDir.resolve(storedFilename);
        if (Files.exists(direct))
            return direct;

        // try with the canonical .jmn suffix
        Path withJmn = storageDir.resolve(storedFilename + ".jmn");
        if (Files.exists(withJmn))
            return withJmn;

        // try to match by prefix or base name (id__orig or id__orig.jmn)
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(storageDir)) {
            for (Path p : ds) {
                if (!Files.isRegularFile(p))
                    continue;
                String fn = p.getFileName().toString();
                if (fn.equalsIgnoreCase(storedFilename))
                    return p;
                if (fn.equalsIgnoreCase(storedFilename + ".jmn"))
                    return p;
                if (fn.startsWith(storedFilename + ""))
                    return p; // prefixed match
                // also allow matching by id (before __) if user passed that
                int idx = fn.indexOf("__");
                if (idx > 0) {
                    String idPart = fn.substring(0, idx);
                    if (idPart.equalsIgnoreCase(storedFilename))
                        return p;
                }
            }
        }
        return null;
    }

    /**
     * Delete a stored file by name (tolerant to renames). Returns true if deleted.
     */
    public boolean deleteStored(String storedFilename) throws IOException {
        Path p = findStoredPath(storedFilename);
        if (p == null)
            return false;
        // attempt secure overwrite before deleting to reduce chance of recovery
        try {
            secureOverwrite(p);
        } catch (Exception e) {
            // fall back to regular delete
        }
        return Files.deleteIfExists(p);
    }

    private void secureOverwrite(Path p) throws IOException {
        long size = Files.size(p);
        if (size <= 0) return;
        try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(p.toFile(), "rw")) {
            raf.seek(0);
            byte[] zeros = new byte[8192];
            long written = 0;
            while (written < size) {
                int toWrite = (int) Math.min(zeros.length, size - written);
                raf.write(zeros, 0, toWrite);
                written += toWrite;
            }
            try { raf.getFD().sync(); } catch (Exception ignore) {}
        }
    }

    public Path getStorageDir() {
        return storageDir;
    }
}
