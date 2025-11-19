
package id.juman.core;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoService {
    public static final int IV_LENGTH = 12;
    public static final int TAG_LENGTH = 128;
    private static final SecureRandom RNG = new SecureRandom();

    public static void encryptFile(File in, File out, SecretKey key) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        RNG.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcm = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcm);
        try (FileOutputStream fos = new FileOutputStream(out);
             FileInputStream fis = new FileInputStream(in);
             CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
            // write iv first
            fos.write(iv);
            byte[] buf = new byte[4096];
            int r;
            while ((r = fis.read(buf)) != -1) cos.write(buf, 0, r);
        }
    }

    public static void decryptFile(File in, File out, SecretKey key) throws Exception {
        try (FileInputStream fis = new FileInputStream(in)) {
            byte[] iv = new byte[IV_LENGTH];
            if (fis.read(iv) != IV_LENGTH) throw new IOException("Invalid file");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcm = new GCMParameterSpec(TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcm);
            try (CipherInputStream cis = new CipherInputStream(fis, cipher);
                 FileOutputStream fos = new FileOutputStream(out)) {
                byte[] buf = new byte[4096];
                int r;
                while ((r = cis.read(buf)) != -1) fos.write(buf, 0, r);
            }
        }
    }

    public static String toBase64(byte[] b){ return Base64.getEncoder().encodeToString(b); }
    public static byte[] fromBase64(String s){ return Base64.getDecoder().decode(s); }
}
