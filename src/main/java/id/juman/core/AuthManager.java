
package id.juman.core;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Properties;

public class AuthManager {
    private static final AuthManager INSTANCE = new AuthManager();
    private final Path dataDir;
    private final Path configFile;
    private final SecureRandom rng = new SecureRandom();

    private String username = "admin";
    private String passwordHash = null; // base64 PBKDF2 hash
    private String passwordSalt = null; // base64 salt
    private boolean passwordChanged = false;
    private SecretKey masterKey;
    private Path masterKeyFile;
    private Path recoveryFile;

    private AuthManager() {
        String userHome = System.getProperty("user.home");
        dataDir = Paths.get(userHome, "Documents", "JuMan");
        configFile = dataDir.resolve("config.properties");
        masterKeyFile = dataDir.resolve("master.key");
        recoveryFile = dataDir.resolve("recovery.txt");
    }

    public static AuthManager getInstance(){ return INSTANCE; }

    public void init() throws IOException {
        if (!Files.exists(dataDir)) Files.createDirectories(dataDir);
        if (!Files.exists(configFile)) {
            Properties p = new Properties();
            p.setProperty("username", username);
            p.setProperty("passwordChanged", "false");
            try (OutputStream os = Files.newOutputStream(configFile)) {
                p.store(os, "JuMan config");
            }
            // generate master key and recovery key
            generateAndStoreMaster();
        } else {
            // load properties and master key
            Properties p = new Properties();
            try (InputStream is = Files.newInputStream(configFile)) { p.load(is); }
            username = p.getProperty("username", username);
            passwordChanged = Boolean.parseBoolean(p.getProperty("passwordChanged", "false"));
            passwordHash = p.getProperty("passwordHash", null);
            passwordSalt = p.getProperty("passwordSalt", null);
            loadMasterKey();
        }
    }

    private void generateAndStoreMaster() throws IOException {
        byte[] key = new byte[32];
        rng.nextBytes(key);
        masterKey = new SecretKeySpec(key, "AES");
        // write master key bytes base64 to master.key (for demo; in prod encrypt this with password-derived key)
        Files.write(masterKeyFile, Base64.getEncoder().encode(key), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        // generate recovery key and store in recovery.txt
        byte[] rec = new byte[32];
        rng.nextBytes(rec);
        String recB64 = Base64.getEncoder().encodeToString(rec);
        Files.writeString(recoveryFile, recB64, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
    }

    private void loadMasterKey() throws IOException {
        if (Files.exists(masterKeyFile)) {
            byte[] b64 = Files.readAllBytes(masterKeyFile);
            byte[] raw = Base64.getDecoder().decode(b64);
            masterKey = new SecretKeySpec(raw, "AES");
        } else {
            generateAndStoreMaster();
        }
    }

    public SecretKey getMasterKey(){ return masterKey; }

    public Path getDataDir(){ return dataDir; }

    public boolean isPasswordChanged(){ return passwordChanged; }

    public boolean verifyPassword(String pwd) {
        if (!passwordChanged || passwordHash == null || passwordSalt == null) return "admin".equals(pwd) && !passwordChanged;
        try {
            byte[] salt = Base64.getDecoder().decode(passwordSalt);
            byte[] hash = pbkdf2(pwd.toCharArray(), salt);
            String h64 = Base64.getEncoder().encodeToString(hash);
            return h64.equals(passwordHash);
        } catch (Exception e){ return false; }
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

    private byte[] pbkdf2(char[] password, byte[] salt) throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        return skf.generateSecret(spec).getEncoded();
    }

    public boolean verifyRecoveryToken(String token) throws IOException {
        if (!Files.exists(recoveryFile)) return false;
        String stored = Files.readString(recoveryFile, StandardCharsets.UTF_8).trim();
        return stored.equals(token.trim());
    }

    public boolean resetPasswordWithRecovery(String token, String newPassword) throws Exception {
        if (verifyRecoveryToken(token)) {
            setPassword(newPassword);
            return true;
        }
        return false;
    }
}
